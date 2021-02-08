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

iq_session = requests.Session
iq_url, iq_auth, debug = "", "", False
categories, organizations, applications, ldap_connections = [], [], [], []
roleType = ['USER', 'GROUP']


def get_arguments():
    global iq_url, iq_session, iq_auth, debug
    parser = argparse.ArgumentParser(description='This script enables you to configure IQ Server from JSON\
     data, thus supporting the config-as-code requirement of Sonatype customers')
    parser.add_argument('-u', '--url', help='', default="http://localhost:8070", required=False)
    parser.add_argument('-a', '--auth', help='', default="admin:admin123", required=False)
    parser.add_argument('-f', '--file_name', default="conf/configuration.json", required=True)
    parser.add_argument('-d', '--debug', default=False, required=False)

    args = vars(parser.parse_args())
    iq_url = args["url"]
    credentials = args["auth"].split(":")
    debug = args["debug"]
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
    nexus_administration()

    # ROOT level configuration
    root_configuration()

    # Iterate over the Organisations
    # process_orgs()

    # Iterate over the Organisations
    if organizations is not None:
        # loops through config data
        for org in organizations:

            # Apply Organisation configuration
            org_configuration(org)

#            for app in org['applications']:
#                if not app['publicId']:
#                    print(f'No publicId {app}')
#
#                # Apply Application configuration
#                if check_application(app) is None and name_available(app['name']):
#                    # Apply Application configuration
#                    app['organizationName'] = org['name']
#                    app_configuration(app)
#                else:
#                    print(f"'{app['name']}' already exists in '{org['name']}'")


def nexus_administration():
    # Parses and applies all the 'administrative' configuration for Nexus IQ
    persist_users()
    persist_roles()
    persist_ldap_instances()
    persist_email_server_connection()
    persist_proxy()
    persist_webhooks()
    persist_system_notice()
    persist_success_metrics()
    persist_auto_applications()
    persist_automatic_scc()
    persist_success_metrics_reports()


def root_configuration():
    # Parses and applies all of the ROOT Org configuration
    persist_application_categories()
    persist_application_grandfathering()
    persist_continuous_monitoring()
    persist_proprietary_components()
    persist_component_labels()
    persist_license_threat_groups()
    persist_data_purging()
    persist_source_control()
    apply_access()

def process_orgs():
    url = f'{iq_url}/api/v2/organizations'
    orgs = get_url(url)
    for org in orgs['organizations']:
        x = 1

    return None

def org_configuration(org):
    # Parses and applies all of the child Org configuration
    persist_application_categories(org['id'])
    persist_component_labels(org['id'])
    persist_license_threat_groups(org['id'])
    persist_application_grandfathering(org['id'])
    persist_continuous_monitoring(org['id'])
    persist_data_purging(org['id'])
    #apply_access(org, org.get('access'), org=org['eid'])
    data = org.get('proprietary_components')
    if data is not None and len(data) > 0:
        data['ownerId'] = org['id']
        persist_proprietary_components(data, org=org['eid'])
    persist_source_control(org['id'])


def app_configuration(app):
    # Parses and applies all of the application configuration
    new_app = add_application(app)
    persist_application_grandfathering(app.get('grandfathering'), app=app['publicId'])
    persist_continuous_monitoring(app.get('continuous_monitoring_stage'), app=app['publicId'])
    eid = new_app['id']
    apply_access(new_app, app.get('access'), app=eid)
    data = app.get('proprietary_components')
    if data is not None and len(data) > 0:
        data['ownerId'] = eid
        persist_proprietary_components(data, app=new_app['publicId'])
    persist_source_control(app.get('source_control'), app=eid)


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
    resp = iq_session.get(url, auth=iq_auth)
    return handle_resp(resp, root)


def post_url(url, params, root=""):
    # common post call
    resp = iq_session.post(url, json=params, auth=iq_auth)
    return handle_resp(resp, root)


def put_url(url, params, root=""):
    # common put call
    resp = iq_session.put(url, json=params, auth=iq_auth)
    return handle_resp(resp, root)


def delete_url(url, params, root=""):
    # common put call
    resp = iq_session.delete(url, json=params, auth=iq_auth)
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
    global categories
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


def get_organization_id(name):
    ret = None
    for org in organizations:
        if name in org['name']:
            ret = org['id']
            break
    return ret

def get_organization_name(id):
    ret = None
    for org in organizations:
        if id in org['id']:
            ret = org['name']
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
    for c in categories:
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
            ret = role['id']
            break
    if len(ret) > 0:
        return {'tagId': ret}
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
        "organizationId": get_organization_id(app['organizationName']),
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
    global categories

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
def apply_role(url, role_id, user_or_group_name, role_type):
    data = {
        "memberMappings": [
            {
                "roleId": role_id,
                "members": [
                    {
                        "type": role_type,
                        "userOrGroupName": user_or_group_name
                    }
                ]
            }
        ]
    }
    put_url(url, data)
    print("Applied RBAC data:")
    print_debug(data)


def apply_access(org='ROOT_ORGANIZATION_ID', app=None):
    url = f'{iq_url}/api/v2/{orgs_or_apps(org, app)}/roleMembers'
    roles = find_available_roles()
    for role in roles:
        x = 1
        # Apply the roles to the application

        # Now apply the roles for the new applications
        # if (check_user(user_or_group_name, users, role_type) is not None) and \
#        if (check_user_or_group(role_type) is not None) and (role_id is not None):
#            # Validation completed, apply the roles!
#            # No return payload with a 204 PUT response!
#            apply_role(url, role_id['tagId'], user_or_group_name, role_type)
#            print(f"to '{role}' for '{role_type}:{user_or_group_name}' to '{entity['name']}'")
#        else:
#            print(f"Unable to apply '{role}' for '{role_type}:{user_or_group_name}' to '{entity['name']}'")

    return None


def persist_auto_applications():
    url = f'{iq_url}/rest/config/automaticApplications'
    auto_apps = get_url(url)
    for org in organizations:
        if org['id'] == auto_apps['parentOrganizationId']:
            auto_apps['parentOrganizationId'] = org['name']
            break
    data = {'automatic_applications': auto_apps}
    persist_data(data, 'scrape/system-auto_applications.json')
    print_debug(data)


def persist_application_grandfathering(org='ROOT_ORGANIZATION_ID', app=None):
    url = f'{iq_url}/rest/policyViolationGrandfathering/{org_or_app(org, app)}'
    data = {'grandfathering': get_url(url)}
    persist_data(data, f'scrape/{get_organization_name(org)}-grandfathering.json')
    print_debug(data)
    return data


def persist_webhooks():
    url = f'{iq_url}/rest/config/webhook'
    data = {'webhooks': []}
    webhooks = get_url(url)
    if not (webhooks is None):
        for webhook in webhooks:
            webhook['id'] = None
            data['webhooks'].append(webhook)

    persist_data(data, 'scrape/system-webhooks.json')
    print_debug(data)
    return data


def persist_proxy():
    # This API applies the config regardless of whether the proxy is already configured.
    url = f'{iq_url}/api/v2/config/httpProxyServer'
    proxy = get_url(url)
    data = {'proxy': proxy}
    persist_data(data, 'scrape/system-proxy.json')
    print_debug(data)
    return data


def persist_source_control(org='ROOT_ORGANIZATION_ID', app=None):
    url = f'{iq_url}/api/v2/sourceControl/{org_or_app(org, app)}'
    # This API applies the config regardless of whether the proxy is already configured.
    sc = get_url(url)
    if sc is not None:
        sc.pop('id')
    data = {'source_control': sc}
    persist_data(data, f'scrape/{get_organization_name(org)}-source_control.json')
    print_debug(data)
    return data


def persist_success_metrics():
    url = f'{iq_url}/rest/successMetrics'
    # This API applies the config regardless of whether the proxy is already configured.
    metrics = get_url(url)
    data = {'success_metrics': metrics}
    persist_data(data, 'scrape/system-success_metrics.json')
    print_debug(data)


def persist_success_metrics_reports():
    url = f'{iq_url}/rest/successMetrics/report'
    # This API applies the config regardless of whether the proxy is already configured.
    success_metrics = get_url(url)
    for sm in success_metrics:
        sm.pop('id')
        sm.pop('scope')
        sm['scope'] = {}

    data = {'success_metrics_reports': success_metrics}
    persist_data(data, 'scrape/system-success_metrics_reports.json')
    print_debug(data)
    return data


def persist_automatic_scc():
    url = f'{iq_url}/rest/config/automaticScmConfiguration'
    # This API applies the config regardless of whether the proxy is already configured.
    data = {'automatic_source_control': get_url(url)}
    persist_data(data, 'scrape/system-automatic_scc.json')
    print_debug(data)
    return data


def persist_proprietary_components(org='ROOT_ORGANIZATION_ID', app=None):
    url = f'{iq_url}/rest/proprietary/{org_or_app(org, app)}'
    # This API applies the config regardless of whether the proxy is already configured.
    pcs = get_url(url)
    pcs = pcs['proprietaryConfigByOwners']
    for pc in pcs:
        data = {'proprietary_components': pc['proprietaryConfig']}
        data['proprietary_components']['id'] = None
        persist_data(data, f'scrape/{get_organization_name(org)}-proprietary_component.json')
        print_debug(data)
    return data

def persist_roles():
    url = f'{iq_url}/rest/security/roles'
    roles = get_url(url)
    for element in roles:
        element.pop('id', None)
    data = {'custom_roles': roles}
    persist_data(data, 'scrape/system_roles.json')
    print_debug(data)
    return data


def persist_continuous_monitoring(org='ROOT_ORGANIZATION_ID', app=None):
    url = f'{iq_url}/rest/policyMonitoring/{org_or_app(org, app)}'
    cms = get_url(url)
    if cms is not None:
        cms.pop('id')
    data = {'continuous_monitoring_stage': cms}
    persist_data(data, f'scrape/{get_organization_name(org)}-continuous_monitoring.json')
    print_debug(data)
    return data


def persist_data_purging(org='ROOT_ORGANIZATION_ID'):
    url = f'{iq_url}/api/v2/dataRetentionPolicies/organizations/{org}'
    data = {'data_purging': get_url(url)}
    persist_data(data, f'scrape/{get_organization_name(org)}-data_purging.json')
    print_debug(data)
    return data


def persist_application_categories(org='ROOT_ORGANIZATION_ID'):
    url = f'{iq_url}/api/v2/applicationCategories/organization/{org}'
    acs = get_url(url)
    if acs is not None:
        for ac in acs:
            ac.pop('id')
            ac.pop('organizationId')

    data = {'application_categories': acs}
    print_debug(data)
    persist_data(data, f'scrape/{get_organization_name(org)}-application_categories.json')
    return data


def persist_component_labels(org='ROOT_ORGANIZATION_ID'):
    url = f'{iq_url}/api/v2/labels/organization/{org}'
    labels = get_url(url)
    if labels is not None:
        for label in labels:
            label.pop('id')
    data = {'component_labels': labels}
    print_debug(data)
    persist_data(data, f'scrape/{get_organization_name(org)}-component_labels.json')
    return data


def persist_license_threat_groups(org='ROOT_ORGANIZATION_ID'):
    url = f'{iq_url}/rest/licenseThreatGroup/organization/{org}'
    ltgs = get_url(url)
    if ltgs is not None:
        for ltg in ltgs:
            ltg.pop('id')
    data = {'license_threat_groups': ltgs}
    print_debug(data)
    persist_data(data, f'scrape/{get_organization_name(org)}-license_threat_groups.json')
    return data


def persist_ldap_instances():
    try:
        url = f'{iq_url}/rest/config/ldap'
        data = {'ldap_connections': []}
        # Connection is created above, so it is expected in the list of connections
        conns = get_url(url)
        if not (conns is None):
            for conn in conns:
                data['ldap_connections'].append(parse_ldap_connection(conn))

        print_debug(data)
        persist_data(data, 'scrape/system-ldap_connections.json')
        return data

    except KeyError as err:
        print("Error parsing: {0}".format(err))


def persist_email_server_connection():
    url = f'{iq_url}/api/v2/config/mail'
    email = get_url(url)
    data = {'email_server': email}
    persist_data(data, 'scrape/system_email.json')
    print_debug(data)
    return data


def persist_users():
    url = f'{iq_url}/rest/user'
    users = get_url(url)
    for element in users:
        element.pop('id', None)
        element.pop('usernameLowercase', None)
    data = {'users': users}
    persist_data(data, "scrape/system_users.json")
    print_debug(data)
    return data


def persist_system_notice():
    url = f'{iq_url}/rest/config/systemNotice'
    notice = get_url(url)
    data = {'system_notice': notice}
    persist_data(data, 'scrape/system-system_notice.json')
    print_debug(data)
    return data


def parse_ldap_connection(conn):
    data = {'name': conn['name']}
    url = f'{iq_url}/rest/config/ldap/{conn["id"]}/connection'
    response = get_url(url)
    response.pop('id', None)
    serverId = response.pop('serverId', None)

    data['connection'] = response
    url = f'{iq_url}/rest/config/ldap/{serverId}/userMapping'
    response = get_url(url)
    response.pop('id', None)
    response.pop('serverId', None)

    data['mappings'] = response
    print("Mapped LDAP connection:")
    return data


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


# Write the data to a file...
def persist_data(data, filename):
    with open(filename, 'w') as outfile:
        json.dump(data, outfile, indent=2)
    print(f'Persisted data to {filename}')


# --------------------------------------------------------------------
if __name__ == "__main__":
    main()
