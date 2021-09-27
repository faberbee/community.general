#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = '''
---
module: keycloak_client_defaultclientscopes

short_description: Allows administration of Keycloak client_defaultclientscopes with the Keycloak API
version_added: 3.5.0

description:
    - This module allows you to add or remove Keycloak a default client scope to a client with the Keycloak REST API.
      It requires access to the REST API via OpenID Connect; the user connecting and the client being
      used must have the requisite access rights. In a default Keycloak installation, admin-cli
      and an admin user would work, as would a separate client definition with the scope tailored
      to your needs and a user having the expected roles.

    - The names of module options are snake_cased versions of the camelCase ones found in the
      Keycloak API and its documentation at U(https://www.keycloak.org/docs-api/8.0/rest-api/index.html).

    - Attributes are multi-valued in the Keycloak API. All attributes are lists of individual values and will
      be returned that way by this module. You may pass single values for attributes when calling the module,
      and this will be translated into a list suitable for the API.

    - When updating a client_defaultclientscopes, where possible provide the client scope ID to the module. This removes a lookup
      to the API to translate the name into the role ID.


options:
    state:
        description:
            - State of the client_defaultclientscopes.
            - On C(present), the client_defaultclientscopes will be created if it does not yet exist, or updated with the parameters you provide.
            - On C(absent), the client_defaultclientscopes will be removed if it exists.
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
    
    default_client_scopes:
        description:
            - Default client scopes to be mapped to the client.
        type: list
        elements: dict
        suboptions:
            name:
                type: str
                description:
                    - Name of the client scope
            id:
                type: str
                description:
                    - The unique identifier for this client scope.
                    - This parameter is not required for updating or deleting a role_representation but
                      providing it will reduce the number of API calls required.

extends_documentation_fragment:
- community.general.keycloak


author:
    - Francesco Fiore (@ffiore)
'''

EXAMPLES = '''
- name: Add default client scopes to a client's default client scopes list, authentication with credentials
  community.general.keycloak_client_defaultclientscopes:
    realm: MyCustomRealm
    auth_client_id: admin-cli
    auth_keycloak_url: https://auth.example.com/auth
    auth_realm: master
    auth_username: USERNAME
    auth_password: PASSWORD
    state: present
    client_id: client1
    default_client_scopes:
      - name: scope_name1
        id: scope_id1
      - name: scope_name2
        id: scope_id2
  delegate_to: localhost

- name: Unmap client scopes from a client scope
  community.general.keycloak_client_defaultclientscopes:
    realm: MyCustomRealm
    auth_client_id: admin-cli
    auth_keycloak_url: https://auth.example.com/auth
    auth_realm: master
    auth_username: USERNAME
    auth_password: PASSWORD
    state: absent
    client_id: client1
    default_client_scopes:
      - name: scope_name1
        id: scope_id1
      - name: scope_name2
        id: scope_id2
  delegate_to: localhost

'''

RETURN = '''
msg:
  description: Message as to what action was taken
  returned: always
  type: str
  sample: "Role role1 assigned to client scope scope1."

proposed:
    description: role_representation representation of proposed changes to client_defaultclientscopes.
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

    client_scope_spec = dict(
        name=dict(type='str'),
        id=dict(type='str'),
    )

    meta_args = dict(
        state=dict(default='present', choices=['present', 'absent']),
        realm=dict(default='master'),
        cid=dict(type='str'),
        client_id=dict(type='str'),
        default_client_scopes=dict(type='list', elements='dict', options=client_scope_spec),
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
    default_client_scopes = module.params.get('default_client_scopes')
    force = module.params.get('force')

    # Check the parameters
    if cid is None and client_id is None:
        module.fail_json(msg='Either the `client_id` or `cid` has to be specified.')

    if cid is None:
        cid = kc.get_client_id(client_id, realm=realm)
        if cid is None:
            module.fail_json(msg='Could not fetch client %s:' % client_id)
    if default_client_scopes is None:
        module.exit_json(msg="Nothing to do (no roles specified).")
    else:
        for client_scope_index, client_scope in enumerate(default_client_scopes, start=0):
            if client_scope['name'] is None and client_scope['id'] is None:
                module.fail_json(msg='Either the `name` or `id` has to be specified on each role.')
            # Fetch missing client_scope id
            if client_scope['id'] is None:
                scope = kc.get_clientscope_by_name(name=client_scope['name'], realm=realm)
                if scope is not None:
                    client_scope['id'] = scope['id']
                else:
                    module.fail_json(msg='Could not fetch client scope %s' % (client_scope['name']))
            # Fetch missing client scope name
            else:
                scope = kc.get_clientscope_by_clientscopeid(client_scope['id'], realm=realm)
                if scope is not None:
                    client_scope['name'] = scope['name']
                else:
                    module.fail_json(msg='Could not fetch client scope %s' % (client_scope['id']))

    assigned_client_scopes_before = kc.get_client_defaultclientscopes(cid, realm=realm)
    available_client_scopes_before = [x for x in kc.get_clientscopes(realm=realm) if x['id'] not in
                                      [s['id'] for s in assigned_client_scopes_before]]

    result['existing'] = assigned_client_scopes_before
    result['proposed'] = default_client_scopes

    update_client_scopes = []
    delete_client_scopes = []
    for client_scope_index, client_scope in enumerate(default_client_scopes, start=0):
        # Fetch client scopes to assign if state present
        if state == 'present':
            for available_client_scope in available_client_scopes_before:
                if client_scope['name'] == available_client_scope['name']:
                    update_client_scopes.append(client_scope)

        # Fetch client scopes to remove if state absent
        else:
            for assigned_client_scope in assigned_client_scopes_before:
                if client_scope['name'] == assigned_client_scope['name']:
                    update_client_scopes.append(client_scope)

    if state == 'present' and force:
        required_client_scopes = [client_scope['name'] for client_scope in default_client_scopes]
        for client_scope in assigned_client_scopes_before:
            if client_scope['name'] not in required_client_scopes:
                delete_client_scopes.append(client_scope)

    if len(update_client_scopes) or len(delete_client_scopes):
        if state == 'present':
            # Assign client scopes
            result['changed'] = True
            if module._diff:
                result['diff'] = dict(before=assigned_client_scopes_before, after=update_client_scopes)
            if module.check_mode:
                module.exit_json(**result)
            for client_scope in update_client_scopes:
                kc.add_client_defaultclientscope(cid=cid, csid=client_scope['id'], realm=realm)
            for client_scope in delete_client_scopes:
                kc.delete_client_defaultclientscope(cid=cid, csid=client_scope['id'], realm=realm)
            result['msg'] = 'Default client scopes %s assigned to client %s.' % (update_client_scopes, client_id)
            assigned_client_scopes_after = kc.get_client_defaultclientscopes(cid, realm=realm)
            result['end_state'] = assigned_client_scopes_after
            module.exit_json(**result)
        else:
            # Remove mapping of client scopes
            result['changed'] = True
            if module._diff:
                result['diff'] = dict(before=assigned_client_scopes_before, after=update_client_scopes)
            if module.check_mode:
                module.exit_json(**result)
            for client_scope in delete_client_scopes:
                kc.delete_client_defaultclientscope(cid=cid, csid=client_scope['id'], realm=realm)
            result['msg'] = 'Client scopes %s removed from client %s.' % (update_client_scopes, client_id)
            assigned_client_scopes_after = kc.get_client_defaultclientscopes(cid=cid, realm=realm)
            result['end_state'] = assigned_client_scopes_after
            module.exit_json(**result)
    # Do nothing
    else:
        result['changed'] = False
        result['msg'] = 'Nothing to do, client scopes %s are correctly mapped with client %s.' % (
            default_client_scopes, client_id)
        module.exit_json(**result)


if __name__ == '__main__':
    main()
