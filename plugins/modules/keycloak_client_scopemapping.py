#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = '''
---
module: keycloak_client_scopemapping

short_description: Allows administration of Keycloak client_scopemapping with the Keycloak API
version_added: 3.5.0

description:
    - This module allows you to add, remove or modify Keycloak client_scopemapping with the Keycloak REST API.
      It requires access to the REST API via OpenID Connect; the user connecting and the client being
      used must have the requisite access rights. In a default Keycloak installation, admin-cli
      and an admin user would work, as would a separate client definition with the scope tailored
      to your needs and a user having the expected roles.

    - The names of module options are snake_cased versions of the camelCase ones found in the
      Keycloak API and its documentation at U(https://www.keycloak.org/docs-api/8.0/rest-api/index.html).

    - Attributes are multi-valued in the Keycloak API. All attributes are lists of individual values and will
      be returned that way by this module. You may pass single values for attributes when calling the module,
      and this will be translated into a list suitable for the API.

    - When updating a client_scopemapping, where possible provide the role ID to the module. This removes a lookup
      to the API to translate the name into the role ID.


options:
    state:
        description:
            - State of the client_scopemapping.
            - On C(present), the client_scopemapping will be created if it does not yet exist, or updated with the parameters you provide.
            - On C(absent), the client_scopemapping will be removed if it exists.
        default: 'present'
        type: str
        choices:
            - present
            - absent

    force:
        type: bool
        description:
            - Force override of scope mapping
        default: False
    
    realm:
        type: str
        description:
            - They Keycloak realm under which this role_representation resides.
        default: 'master'

    client_scope_name:
        type: str
        description:
            - Name of the client scope to be mapped.
            - This parameter is required (can be replaced by gid for less API call).

    csid:
        type: str
        description:
            - Id of the client scope to be mapped.
            - This parameter is not required for updating or deleting the scopemapping but
              providing it will reduce the number of API calls required.

    client_id:
        type: str
        description:
            - Name of the client to be mapped (different than I(cid)).
            - This parameter is required (can be replaced by cid for less API call).

    cid:
        type: str
        description:
            - Id of the client to be mapped.
            - This parameter is not required for updating or deleting the scopemapping but
              providing it will reduce the number of API calls required.

    roles:
        description:
            - Roles to be mapped to the client scope.
        type: list
        elements: dict
        suboptions:
            name:
                type: str
                description:
                    - Name of the role_representation.
                    - This parameter is required only when creating or updating the role_representation.
            id:
                type: str
                description:
                    - The unique identifier for this role_representation.
                    - This parameter is not required for updating or deleting a role_representation but
                      providing it will reduce the number of API calls required.

extends_documentation_fragment:
- community.general.keycloak


author:
    - Francesco Fiore (@ffiore)
'''

EXAMPLES = '''
- name: Map a client role to a client scope, authentication with credentials
  community.general.keycloak_client_scopemapping:
    realm: MyCustomRealm
    auth_client_id: admin-cli
    auth_keycloak_url: https://auth.example.com/auth
    auth_realm: master
    auth_username: USERNAME
    auth_password: PASSWORD
    state: present
    client_id: client1
    client_scope_name: scope1
    roles:
      - name: role_name1
        id: role_id1
      - name: role_name2
        id: role_id2
  delegate_to: localhost

- name: Map a client role to a client scope, authentication with token
  community.general.keycloak_client_scopemapping:
    realm: MyCustomRealm
    auth_client_id: admin-cli
    auth_keycloak_url: https://auth.example.com/auth
    token: TOKEN
    state: present
    client_id: client1
    client_scope_name: scope1
    roles:
      - name: role_name1
        id: role_id1
      - name: role_name2
        id: role_id2
  delegate_to: localhost

- name: Unmap client role from a client scope
  community.general.keycloak_client_scopemapping:
    realm: MyCustomRealm
    auth_client_id: admin-cli
    auth_keycloak_url: https://auth.example.com/auth
    auth_realm: master
    auth_username: USERNAME
    auth_password: PASSWORD
    state: absent
    client_id: client1
    client_scope_name: scope1
    roles:
      - name: role_name1
        id: role_id1
      - name: role_name2
        id: role_id2
  delegate_to: localhost

'''

RETURN = '''
msg:
  description: Message as to what action was taken
  returned: always
  type: str
  sample: "Role role1 assigned to client scope scope1."

proposed:
    description: role_representation representation of proposed changes to client_scopemapping.
    returned: always
    type: dict
    sample: {
      clientId: "test"
    }
existing:
    description:
      - role_representation representation of existing role_representation.
      - The sample is truncated.
    returned: always
    type: dict
    sample: {
        "adminUrl": "http://www.example.com/admin_url",
        "attributes": {
            "request.object.signature.alg": "RS256",
        }
    }
end_state:
    description:
      - role_representation representation of role_representation after module execution.
      - The sample is truncated.
    returned: always
    type: dict
    sample: {
        "adminUrl": "http://www.example.com/admin_url",
        "attributes": {
            "request.object.signature.alg": "RS256",
        }
    }
'''

from ansible_collections.community.general.plugins.module_utils.identity.keycloak.keycloak import KeycloakAPI, \
    keycloak_argument_spec, get_token, KeycloakError
from ansible.module_utils.basic import AnsibleModule


def main():
    """
    Module execution

    :return:
    """
    argument_spec = keycloak_argument_spec()

    roles_spec = dict(
        name=dict(type='str'),
        id=dict(type='str'),
    )

    meta_args = dict(
        state=dict(default='present', choices=['present', 'absent']),
        realm=dict(default='master'),
        client_scope_name=dict(type='str'),
        csid=dict(type='str'),
        cid=dict(type='str'),
        client_id=dict(type='str'),
        roles=dict(type='list', elements='dict', options=roles_spec),
        force=dict(type='bool', default=False)
    )

    argument_spec.update(meta_args)

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           required_one_of=([['token', 'auth_realm', 'auth_username', 'auth_password']]),
                           required_together=([['auth_realm', 'auth_username', 'auth_password']]))

    result = dict(changed=False, msg='', diff={}, proposed={}, existing={}, end_state={})

    # Obtain access token, initialize API
    try:
        connection_header = get_token(module.params)
    except KeycloakError as e:
        module.fail_json(msg=str(e))

    kc = KeycloakAPI(module, connection_header)

    realm = module.params.get('realm')
    state = module.params.get('state')
    cid = module.params.get('cid')
    client_id = module.params.get('client_id')
    csid = module.params.get('csid')
    client_scope_name = module.params.get('client_scope_name')
    roles = module.params.get('roles')
    force = module.params.get('force')

    # Check the parameters
    if cid is None and client_id is None:
        module.fail_json(msg='Either the `client_id` or `cid` has to be specified.')
    if csid is None and client_scope_name is None:
        module.fail_json(msg='Either the `client_scope_name` or `csid` has to be specified.')

    # Get the potential missing parameters
    if csid is None:
        client_scope_rep = kc.get_clientscope_by_name(client_scope_name, realm=realm)
        if client_scope_rep is not None:
            csid = client_scope_rep['id']
        else:
            module.fail_json(msg='Could not fetch client_scope %s:' % client_scope_name)
    if cid is None:
        cid = kc.get_client_id(client_id, realm=realm)
        if cid is None:
            module.fail_json(msg='Could not fetch client %s:' % client_id)
    if roles is None:
        module.exit_json(msg="Nothing to do (no roles specified).")
    else:
        for role_index, role in enumerate(roles, start=0):
            if role['name'] is None and role['id'] is None:
                module.fail_json(msg='Either the `name` or `id` has to be specified on each role.')
            # Fetch missing role_id
            if role['id'] is None:
                role_id = kc.get_client_role_id_by_name(cid=cid, name=role['name'], realm=realm)
                if role_id is not None:
                    role['id'] = role_id
                else:
                    module.fail_json(msg='Could not fetch role %s:' % (role['name']))
            # Fetch missing role_name
            else:
                role['name'] = kc.get_client_role_by_id(cid, role['id'], realm=realm)['name']
                if role['name'] is None:
                    module.fail_json(msg='Could not fetch role %s' % (role['id']))

    # Get effective client-level role mappings
    available_roles_before = kc.get_clientscope_available_client_scopemappings(csid, cid, realm=realm)
    assigned_roles_before = kc.get_clientscope_composite_client_scopemappings(csid, cid, realm=realm)

    result['existing'] = assigned_roles_before
    result['proposed'] = roles

    update_roles = []
    delete_roles = []
    for role_index, role in enumerate(roles, start=0):
        # Fetch roles to assign if state present
        if state == 'present':
            for available_role in available_roles_before:
                if role['name'] == available_role['name']:
                    update_roles.append(role['name'])

        # Fetch roles to remove if state absent
        else:
            for assigned_role in assigned_roles_before:
                if role['name'] == assigned_role['name']:
                    update_roles.append(role['name'])

    if state == 'present' and force:
        required_roles = [role['name'] for role in roles]
        for role in assigned_roles_before:
            if role['name'] not in required_roles:
                delete_roles.append(role['name'])

    if len(update_roles) or len(delete_roles):
        if state == 'present':
            # Assign roles
            result['changed'] = True
            if module._diff:
                result['diff'] = dict(before=assigned_roles_before, after=update_roles)
            if module.check_mode:
                module.exit_json(**result)
            if len(update_roles):
                kc.create_clientscope_client_scopemappings(csid, cid, update_roles, realm=realm)
            if len(delete_roles):
                kc.delete_clientscope_client_scopemappings(csid, cid, delete_roles, realm=realm)
            result['msg'] = 'Roles %s assigned to client scope %s.' % (update_roles, client_scope_name)
            assigned_roles_after = kc.get_clientscope_client_scopemappings(csid, cid, realm=realm)
            result['end_state'] = assigned_roles_after
            module.exit_json(**result)
        else:
            # Remove mapping of role
            result['changed'] = True
            if module._diff:
                result['diff'] = dict(before=assigned_roles_before, after=update_roles)
            if module.check_mode:
                module.exit_json(**result)
            kc.delete_clientscope_client_scopemappings(csid, cid, update_roles, realm=realm)
            result['msg'] = 'Roles %s removed from client scope %s.' % (update_roles, client_scope_name)
            assigned_roles_after = kc.get_clientscope_client_scopemappings(csid, cid, realm=realm)
            result['end_state'] = assigned_roles_after
            module.exit_json(**result)
    # Do nothing
    else:
        result['changed'] = False
        result['msg'] = 'Nothing to do, roles %s are correctly mapped with client scope %s.' % (
        roles, client_scope_name    )
        module.exit_json(**result)


if __name__ == '__main__':
    main()
