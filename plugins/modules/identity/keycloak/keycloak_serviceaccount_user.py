#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = '''
---
module: keycloak_serviceaccount_user

short_description: Fetch the user dedicated to a service account with the Keycloak API
version_added: 3.5.0

description:
    - This module allows you to fetch Keycloak user dedicated to a service account with the Keycloak REST API.
      It requires access to the REST API via OpenID Connect; the user connecting and the client being
      used must have the requisite access rights. In a default Keycloak installation, admin-cli
      and an admin user would work, as would a separate client definition with the scope tailored
      to your needs and a user having the expected roles.

    - The names of module options are snake_cased versions of the camelCase ones found in the
      Keycloak API and its documentation at U(https://www.keycloak.org/docs-api/8.0/rest-api/index.html).

    - Attributes are multi-valued in the Keycloak API. All attributes are lists of individual values and will
      be returned that way by this module. You may pass single values for attributes when calling the module,
      and this will be translated into a list suitable for the API.



options:
    realm:
        type: str
        description:
            - They Keycloak realm under which this role_representation resides.
        default: 'master'

    client_id:
        type: str
        description:
            - Name of the client (different than I(cid)).
            - This parameter is required (can be replaced by cid for less API call).

    cid:
        type: str
        description:
            - Id of the client.
            - This parameter is required (can be replaced by client_id).

extends_documentation_fragment:
- community.general.keycloak


author:
    - Francesco Fiore (@ffiore)
'''

EXAMPLES = '''
- name: Get a service account user
  community.general.keycloak_serviceaccount_user:
    realm: MyCustomRealm
    auth_client_id: admin-cli
    auth_keycloak_url: https://auth.example.com/auth
    auth_realm: master
    auth_username: USERNAME
    auth_password: PASSWORD
    client_id: test-client
  delegate_to: localhost
  register: service_account_user
'''

RETURN = '''
msg:
  description: Message as to what action was taken
  returned: always
  type: str
  sample: "Service account user found"

user:
    description: user_representation representation of user dedicated to the service account.
    returned: success
    type: dict
    sample: {
      id: "uuid",
      username: "user.name"
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

    meta_args = dict(
        realm=dict(default='master'),
        cid=dict(type='str'),
        client_id=dict(type='str'),
    )

    argument_spec.update(meta_args)

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           required_one_of=([['token', 'auth_realm', 'auth_username', 'auth_password']]),
                           required_together=([['auth_realm', 'auth_username', 'auth_password']]))

    result = dict(changed=False, msg='', user={})

    # Obtain access token, initialize API
    try:
        connection_header = get_token(module.params)
    except KeycloakError as e:
        module.fail_json(msg=str(e))

    kc = KeycloakAPI(module, connection_header)

    realm = module.params.get('realm')
    cid = module.params.get('cid')
    client_id = module.params.get('client_id')

    if cid is None and client_id is None:
        module.fail_json(msg='Either the `client_id` or `cid` has to be specified.')

    if cid is None:
        cid = kc.get_client_id(client_id, realm=realm)
        if cid is None:
            module.fail_json(msg='Could not fetch client %s' % client_id)

    client = kc.get_client_by_id(cid, realm=realm)
    if not client:
        module.fail_json(msg='Could not fetch client with id %s' % cid)

    if not client['serviceAccountsEnabled']:
        module.fail_json(msg='Client %s is not a service account' % client_id)

    if not client_id:
        client_id = client['id']

    user = kc.get_client_serviceaccountuser(cid, realm=realm)
    if not user:
        module.fail_json(msg='User not found - client %s is not a service account' % client_id)

    result['user'] = user
    result['msg'] = 'User %s found for service account %s' % (user, client_id)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
