#!/usr/bin/env python3

#
# Copyright 2019-Present Sonatype Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import argparse
import json
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
iq_session = requests.Session
iq_url, iq_auth, debug = "", "", False
app_categories, organizations, applications, ldap_connections = [], [], [], []
roleType = ['USER', 'GROUP']
self_signed = False

def get_arguments():
    global iq_url, iq_session, iq_auth, debug, self_signed
    parser = argparse.ArgumentParser(description='This script enables you to configure IQ Server from JSON\
     data, thus supporting the config-as-code requirement of Sonatype customers')
    parser.add_argument('-u', '--url', help='', default="http://localhost:8070", required=False)
    parser.add_argument('-a', '--auth', help='', default="admin:admin123", required=False)
    parser.add_argument('-f', '--file_name', default="conf/configuration.json", required=True)
    parser.add_argument('-d', '--debug', default=False, required=False)
    parser.add_argument('-s', '--self_signed', default=False, required=False)

    args = vars(parser.parse_args())
    iq_url = args["url"]
    credentials = args["auth"].split(":")
    debug = args["debug"]
    self_signed = args["self_signed"]
    iq_session = requests.Session()
    iq_session.cookies.set('CLM-CSRF-TOKEN', 'api')
    iq_session.headers = {'X-CSRF-TOKEN': 'api'}
    # load user credentials, recommended to use admin account to avoid on-boarding errors.
    iq_auth = requests.auth.HTTPBasicAuth(credentials[0], credentials[1])
    iq_session.auth = iq_auth
    return args


def main():
    # grab defaults or args passed into script.
    args = get_arguments()
    file_name = args["file_name"]

    # store current applications, categories, and organizations
    set_categories()
    set_organizations()
    set_applications()

    with open(file_name) as json_file:
        config = json.load(json_file)

    # Admin level configuration and integrations
    nexus_administration(config)

    # ROOT level configuration
    root_configuration(config)

    # Iterate over the Organisations
    organisations = config.get('organizations')
    if organisations is not None:
        # loops through config data
        for org in organisations:

            # Apply for new organisations and applications
            eid = check_organization(org['name'])
            if eid is None:
                org['eid'] = add_organization(org['name'])
            else:
                org['eid'] = eid

            # Apply Organisation configuration
            org_configuration(org)

            for app in org['applications']:
                if not app['publicId']:
                    print(f'No publicId {app}')

                # Apply Application configuration
                if check_application(app) is None and name_available(app['name']):
                    # Apply Application configuration
                    app['organizationName'] = org['name']
                    app_configuration(app)
                else:
                    print(f"'{app['name']}' already exists in '{org['name']}'")


def nexus_administration(config):
    # Parses and applies all the 'administrative' configuration for Nexus IQ
    create_users(config.get('users'))
    custom_roles(config.get('custom_roles'))
    create_ldap_instances(config.get('ldap_connections'))
    create_email_server_connection(config.get('email_server'))
    add_proxy(config.get('proxy'))
    add_webhooks(config.get('webhooks'))
    add_system_notice(config.get('system_notice'))
    add_success_metrics(config.get('success_metrics'))
    apply_auto_applications(config.get('automatic_applications'))
    add_automatic_scc(config.get('automatic_source_control'))
    add_success_metrics_reports(config.get('success_metrics_reports'))


def root_configuration(config):
    # Parses and applies all of the ROOT Org configuration
    application_categories(config.get('application_categories'))
    application_grandfathering(config.get('grandfathering'))
    continuous_monitoring(config.get('continuous_monitoring_stage'))
    add_proprietary_components(config.get('proprietary_components'))
    component_labels(config.get('component_labels'))
    license_threat_groups(config.get('license_threat_groups'))
    data_purging(config.get('data_purging'))
    add_source_control(config.get('source_control'))
    add_policy(data=config.get('policy'))
    entity = dict()
    entity['name'] = "Root Organisation"
    apply_access(entity, config.get('access'))


def org_configuration(org):
    # Parses and applies all of the child Org configuration
    application_categories(org.get('application_categories'), org['eid'])
    component_labels(org.get('component_labels'), org['eid'])
    license_threat_groups(org.get('license_threat_groups'), org['eid'])
    application_grandfathering(org.get('grandfathering'), org=org['eid'])
    continuous_monitoring(org.get('continuous_monitoring_stage'), org=org['eid'])
    data_purging(org.get('data_purging'), org['eid'])
    apply_access(org, org.get('access'), org=org['eid'])
    add_policy(data=org.get('policy'), org=org['eid'])
    data = org.get('proprietary_components')
    if data is not None and len(data) > 0:
        for ppc in data:
            ppc['ownerId'] = org['eid']
            add_proprietary_components(ppc, org=org['eid'])
    add_source_control(org.get('source_control'), org=org['eid'])


def app_configuration(app):
    # Parses and applies all of the application configuration
    new_app = add_application(app)
    application_grandfathering(app.get('grandfathering'), app=app['publicId'])
    continuous_monitoring(app.get('continuous_monitoring_stage'), app=app['publicId'])
    eid = new_app['id']
    apply_access(new_app, app.get('access'), app=eid)
    add_policy(data=app.get('policy'), app=eid)
    data = app.get('proprietary_components')
    if data is not None and len(data) > 0:
        for ppc in data:
            ppc['ownerId'] = eid
            add_proprietary_components(ppc, app=new_app['publicId'])
    add_source_control(app.get('source_control'), app=eid)


def print_debug(c):
    # testing json output to console
    if debug:
        print(json.dumps(c, indent=4))


def handle_resp(resp, root=""):
    # normalize api call responses
    if resp.status_code != 200:
        print(resp.text)
        return None
    node = resp.json()

    if root in node:
        node = node[root]
    if node is None or len(node) == 0:
        return None
    return node


def get_url(url, root=""):
    # common get call
    resp = iq_session.get(url, auth=iq_auth, verify=not self_signed)
    return handle_resp(resp, root)


def post_url(url, params, root=""):
    # common post call
    resp = iq_session.post(url, json=params, auth=iq_auth, verify=not self_signed)
    return handle_resp(resp, root)

def multipart_post_url(url, data, root=""):
    encoded = json.dumps(data, indent=1).encode('utf-8')
    files = {
        'file': (
            f'policy.json',
            encoded,
            'multipart/form-data'
        )
    }
    resp = iq_session.post(url, files=files, auth=iq_auth, verify=not self_signed)
    return handle_resp(resp, root)

def put_url(url, params, root=""):
    # common put call
    resp = iq_session.put(url, json=params, auth=iq_auth, verify=not self_signed)
    return handle_resp(resp, root)


def delete_url(url, params, root=""):
    # common put call
    resp = iq_session.delete(url, json=params, auth=iq_auth, verify=not self_signed)
    return handle_resp(resp, root)


def org_or_app(org, app):
    if app:
        return f'application/{app}'
    if org is None:
        org = 'ROOT_ORGANIZATION_ID'
    return f'organization/{org}'


def orgs_or_apps(org, app):
    if app:
        return f'applications/{app}'
    if org is None:
        org = 'ROOT_ORGANIZATION_ID'
    return f'organizations/{org}'


# --------------------------------------------------------------------------


def set_applications():
    global applications
    url = f'{iq_url}/api/v2/applications'
    applications = get_url(url, "applications")


def set_organizations():
    global organizations
    url = f'{iq_url}/api/v2/organizations'
    organizations = get_url(url, "organizations")


def set_categories():
    global app_categories
    # using categories from root organization.
    url = f'{iq_url}/api/v2/applicationCategories/organization/ROOT_ORGANIZATION_ID'
    categories = get_url(url)


def check_application(new_app):
    # name is required, default to PublicId
    if not new_app['name']:
        new_app['name'] = new_app['publicId']

    # Look to see if new app already exists
    for app in applications:
        if app['publicId'] == new_app['publicId']:
            return app
    return None


def check_organization(name):
    ret = None
    for org in organizations:
        if name == org['name']:
            ret = org['id']
            break
    return ret


def check_ldap_connection(name):
    ret = ''
    for connection in ldap_connections:
        if name in connection['name']:
            ret = connection['id']
    if len(ret) == 0:
        ret = add_ldap_connection(name)
    if len(ret) > 0:
        return ret
    else:
        return None


def check_categories(app_tags):
    # If the application category does not exist, it will be added to the root organisation by default, by design.
    ret = []
    for tag in app_tags:
        tag_ = check_category(tag)
        if tag_ is not None:
            ret.append(tag_)
    return ret


def check_category(name):
    ret = ''
    if len(name) == 0:
        return None
    for c in app_categories:
        if name['name'] == c['name']:
            ret = c['id']
            break
    if len(ret) == 0:
        ret = add_category(name['name'])
    if len(ret) > 0:
        return {'tagId': ret}
    return None


def check_roles(name, roles):
    ret = ''
    if len(name) == 0:
        return None
    for role in roles:
        if name in role['name']:
            return role['id']
    print(f"Role {name} is not available within Nexus IQ")
    return None


def check_user_or_group(user_or_group):
    if len(user_or_group) == 0:
        return None
    if (user_or_group.upper() == "GROUP") or (user_or_group.upper() == "USER"):
        return user_or_group.upper()

    print(f"User type '{user_or_group}' does not exist! 'USER' or 'GROUP' are the valid types.")
    return None


def add_application(app):
    data = {
        "publicId": app['publicId'],
        "name": app['name'],
        "organizationId": check_organization(app['organizationName']),
        "applicationTags": check_categories(app['applicationTags'])
    }
    response = post_url(f'{iq_url}/api/v2/applications', data)
    print('Added application:')
    print_debug(data)

    if response is not None:
        print(f"added {app['publicId']} to {app['organizationName']}: {response['id']}")
        applications.append(response)

    return response


def add_organization(org_name):
    data = {"name": org_name}
    url = f'{iq_url}/api/v2/organizations'
    resp = post_url(url, data)
    if resp is not None:
        organizations.append(resp)
        return resp['id']
    return ''


def add_ldap_connection(ldap_conn_name):
    data = {"name": ldap_conn_name}
    url = f'{iq_url}/rest/config/ldap'
    resp = post_url(url, data)
    if resp is not None:
        ldap_connections.append(resp)
        print(f"Created LDAP connection: {ldap_conn_name}")
        return resp['id']
    return ''


def add_category(name):
    global app_categories

    url = f'{iq_url}/api/v2/applicationCategories/organization/ROOT_ORGANIZATION_ID'
    data = {"name": name,
            "color": "dark-blue",
            "description": name
            }
    resp = post_url(url, data)
    if resp is not None:
        categories.append(resp)
        return resp['id']
    return ''


# Apply roles to the endpoint identified within the URL
def apply_role(url, role, role_id, access):

    data = {}
    data['memberMappings'] = []

    for user in access:
        if user['role'] == role:
            if len(data['memberMappings']) == 0:
                map = {}
                data['memberMappings'].append(map)
                map['roleId'] = role_id
                map['members'] = []

            mapping = data['memberMappings'][0]
            member = {}
            mapping['members'].append(member)
            member['type'] = user['role_type']
            member['userOrGroupName'] = user['user_or_group_name']

    put_url(url, data)
    print("Applied RBAC data:")
    print_debug(data)


def apply_access(entity, access, org=None, app=None):
    if access is None:
        return
    url = f'{iq_url}/api/v2/{orgs_or_apps(org, app)}/roleMembers'
    iq_roles = None
    if len(access) > 0:
        iq_roles = find_available_roles()

    for acc in access:
        # Apply the roles to the application
        role = acc['role']
        role_id = check_roles(role, iq_roles)
        user_or_group_name = acc['user_or_group_name']
        role_type = acc['role_type']

        # Now apply the roles for the new applications
        # if (check_user(user_or_group_name, users, role_type) is not None) and \
        if (check_user_or_group(role_type) is not None) and (role_id is not None):
            # Validation completed, apply the roles!
            # No return payload with a 204 PUT response!
            apply_role(url, role, role_id, access)
            print(f"to '{role}' for '{role_type}:{user_or_group_name}' to '{entity['name']}'")
        else:
            print(f"Unable to apply '{role}' for '{role_type}:{user_or_group_name}' to '{entity['name']}'")

    return None


def apply_auto_applications(data):
    if data is None or len(data) == 0:
        return
    eid = check_organization(data['parentOrganizationId'])
    data['parentOrganizationId'] = eid
    url = f'{iq_url}/rest/config/automaticApplications'
    put_url(url, data)
    print('Applied Automatic Application configuration:')
    print_debug(data)


def application_grandfathering(data, org=None, app=None):
    if data is None or len(data) == 0:
        return
    url = f'{iq_url}/rest/policyViolationGrandfathering/{org_or_app(org, app)}'
    put_url(url, data)
    print('Applied Grandfathering configuration:')
    print_debug(data)


def add_webhooks(data):
    if data is None or len(data) == 0:
        return
    url = f'{iq_url}/rest/config/webhook'

    # This endpoint allows duplicate identical webhooks to be created.
    # So this script will mitigate this, so you don't run the script repeatedly and duplicate your webhook config!
    for webhook in data:
        response = get_url(url)

        # Iterate over the existing webhooks and bail out if the webhook already exists
        if not (response is None):
            for existing in response:
                if existing['description'] == webhook['description']:
                    print(f"Webhook '{webhook['description']}' already exists!")
                    return

        # Add the new webhook from the config
        post_url(url, webhook)
        print('Added Webhook configuration:')
        print_debug(webhook)


def add_proxy(data):
    if data is None or len(data) == 0:
        return
    # This API applies the config regardless of whether the proxy is already configured.
    url = f'{iq_url}/api/v2/config/httpProxyServer'

    if get_url(url) is None:
        put_url(url, data)
        print('Added proxy server configuration:')
        print_debug(data)
    else:
        print('Proxy server configuration already exists.')


def add_source_control(data, org=None, app=None):
    if data is None or len(data) == 0:
        return
    url = f'{iq_url}/api/v2/sourceControl/{org_or_app(org, app)}'
    # This API applies the config regardless of whether the proxy is already configured.
    if get_url(url) is None:
        post_url(url, data)
        print('Added source control configuration:')
        print_debug(data)
    else:
        print('Source control configuration already exists.')


def add_policy(data, org='ROOT_ORGANIZATION_ID', app=None):
    # importing policy at the application level is not currently supported; only org
    if data is None or len(data) == 0 or app is not None:
        return
    url = f'{iq_url}/rest/policy/{org_or_app(org, app)}/import'
    multipart_post_url(url, data)


def add_success_metrics(data):
    if data is None or len(data) == 0:
        return
    url = f'{iq_url}/rest/successMetrics'
    # This API applies the config regardless of whether the proxy is already configured.
    put_url(url, data)
    print('Added Success Metrics configuration:')
    print_debug(data)


def add_success_metrics_reports(data):
    if data is None or len(data) == 0:
        return
    url = f'{iq_url}/rest/successMetrics/report'
    for sm in data:
        post_url(url, sm)

    print('Added Success Metrics Reporting configuration:')
    print_debug(data)


def add_automatic_scc(data):
    if data is None or len(data) == 0:
        return
    url = f'{iq_url}/rest/config/automaticScmConfiguration'
    # This API applies the config regardless of whether the proxy is already configured.
    put_url(url, data)
    print('Added automatic source control configuration:')
    print_debug(data)


def add_proprietary_components(data, org=None, app=None):
    if data is None or len(data) == 0:
        return
    url = f'{iq_url}/rest/proprietary/{org_or_app(org, app)}'
    # This API applies the config regardless of whether the proxy is already configured.
    put_url(url, data)
    print('Added proprietary components configuration:')
    print_debug(data)


def custom_roles(data):
    if data is None or len(data) == 0:
        return
    url = f'{iq_url}/rest/security/roles'
    for role in data:
        response = post_url(url, role)
        if not (response is None):
            print('Added Custom Role configuration:')
            print_debug(role)


def continuous_monitoring(cm_data, org=None, app=None):
    if cm_data is None or len(cm_data) == 0:
        return
    cm_data['stageTypeId'] = cm_data['stageTypeId'].lower()

    url = f'{iq_url}/rest/policyMonitoring/{org_or_app(org, app)}'

    if cm_data['stageTypeId'].lower() == 'do not monitor':
        delete_url(url, None)
    else:
        put_url(url, cm_data)

    print('Applied Continuous Monitoring configuration:')
    print_debug(cm_data)


def data_purging(data, org='ROOT_ORGANIZATION_ID'):
    if data is None or len(data) == 0:
        return
    url = f'{iq_url}/api/v2/dataRetentionPolicies/organizations/{org}'
    put_url(url, data)
    print('Applied Data Purging configuration:')
    print_debug(data)


def application_categories(data, org='ROOT_ORGANIZATION_ID'):
    if data is None or len(data) == 0:
        return

    url = f'{iq_url}/api/v2/applicationCategories/organization/{org}'

    for app_cat in data:
        resp = post_url(url, app_cat)
        if resp is not None:
            app_categories.append(resp)
        print('Applied Application Category configuration:')
        print_debug(app_cat)


def component_labels(data, org='ROOT_ORGANIZATION_ID'):
    if data is None or len(data) == 0:
        return
    url = f'{iq_url}/api/v2/labels/organization/{org}'
    for label in data:
        if not (post_url(url, label) is None):
            print('Applied Component Label configuration:')
            print_debug(label)


def license_threat_groups(data, org='ROOT_ORGANIZATION_ID'):
    if data is None or len(data) == 0:
        return
    for ltg in data:
        url = f'{iq_url}/rest/licenseThreatGroup/organization/{org}'
        licenses = ltg.pop('licenses')
        ltgResp = post_url(url, ltg)
        if (ltgResp is not None):
            url = f'{iq_url}/rest/licenseThreatGroupLicense/organization/{org}/{ltgResp.pop("id")}'
            put_url(url, licenses)
            print('Applied License Threat Group configuration:')
            ltg['licenses'] = licenses
            print_debug(ltg)


def create_ldap_instances(ldap_conns):
    if ldap_conns is None or len(ldap_conns) == 0:
        return
    for ldap_conn in ldap_conns:
        create_ldap_instance(ldap_conn)


def create_email_server_connection(data):
    if data is None or len(data) == 0:
        return
    url = f'{iq_url}/api/v2/config/mail'
    put_url(url, data)
    print("Added Email Server:")
    print_debug(data)


def create_users(data):
    if data is None or len(data) == 0:
        return
    url = f'{iq_url}/rest/user'
    for user in data:
        post_url(url, user)
        print("Added User:")
        print_debug(data)


def add_system_notice(data):
    if data is None or len(data) == 0:
        return
    url = f'{iq_url}/rest/config/systemNotice'
    put_url(url, data)
    print("Applied System Notice:")
    print_debug(data)


def create_ldap_instance(ldap_conn):
    if len(ldap_conn) == 0:
        return
    try:
        url = f'{iq_url}/rest/config/ldap'

        # Connection is created above, so it is expected in the list of connections
        conns = get_url(url)
        if not (conns is None):
            for conn in conns:
                if conn['name'] == ldap_conn['name']:
                    print('LDAP connection already exists!')
                    return

        conn_id = check_ldap_connection(ldap_conn['name'])
        apply_ldap_connection(conn_id, ldap_conn)
        apply_ldap_mappings(ldap_conn)

    except KeyError as err:
        print("Error parsing: {0}".format(err))


def apply_ldap_connection(conn_id, ldap_conn):
    url = f'{iq_url}/rest/config/ldap/{conn_id}/connection'
    data = ldap_conn['connection']
    data['serverId'] = conn_id
    response = put_url(url, data)
    print("Applied LDAP connection:")
    print_debug(data)
    return response


def apply_ldap_mappings(ldap_conn):
    url = f'{iq_url}/rest/config/ldap/{ldap_conn["connection"]["serverId"]}/userMapping'
    data = ldap_conn['mappings']
    data['serverId'] = ldap_conn['connection']['serverId']
    data['id'] = None
    response = put_url(url, data)
    print("Mapped LDAP connection:")
    print_debug(data)
    return response


def find_available_roles():
    url = f'{iq_url}/api/v2/applications/roles'
    resp = get_url(url)
    if resp is not None:
        return resp['roles']
    return ''


def name_available(name):
    for app in applications:
        if app['name'] == name:
            return False
    return True


# --------------------------------------------------------------------
if __name__ == "__main__":
    main()
