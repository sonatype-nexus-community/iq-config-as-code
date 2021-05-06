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
import os

from requests.packages.urllib3.exceptions import InsecureRequestWarning
from copy import deepcopy

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
iq_session = requests.Session
iq_url, iq_auth, output_dir, debug = "", "", "", False
categories, organizations, applications, ldap_connections, entities = [], [], [], [], []
roleType = ['USER', 'GROUP']
roles = {}
self_signed = False


def get_arguments():
    global iq_url, iq_session, iq_auth, output_dir, debug, self_signed, entities
    parser = argparse.ArgumentParser(description='This script enables you to persist the configuration of IQ Server to JSON\
     data, thus supporting the config-as-code requirement of Sonatype customers')
    parser.add_argument('-u', '--url', help='', default="http://localhost:8070", required=False)
    parser.add_argument('-a', '--auth', help='', default="admin:admin123", required=False)
    parser.add_argument('-o', '--output', default="./scrape", required=False)
    parser.add_argument('-d', '--debug', default=False, required=False)
    parser.add_argument('-s', '--self_signed', default=False, required=False)
    parser.add_argument('-y', '--scope', default="all", required=False)

    args = vars(parser.parse_args())
    iq_url = args["url"]
    credentials = args["auth"].split(":")
    output_dir = args["output"]
    if output_dir[-1] != '/':
        output_dir += '/'

    debug = args["debug"]
    self_signed = args["self_signed"]
    entities = args["scope"].split(",")
    # Remove outer whitespace from entity (org, app)
    entities2 = []

    for entity in entities:
        if entity.strip() not in entities:
            entities2.append(entity.strip())
        else:
            entities2.append(entity)

    entities = entities2
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

    # Create the 'output' directory
    try:
        os.makedirs(output_dir, 0o755);
    except FileExistsError:
        if os.access(output_dir, os.W_OK) is False:
            print(f"Directory {output_dir} is not writeable!")
            return


    # store current applications, categories, and organizations
    set_categories()
    set_organizations()
    set_applications()
    set_roles()

    # Admin level configuration and integrations
    nexus_administration()

    data = {}

    # Iterate over the Organisations
    if organizations is not None:
        orgs = []
        # loops through config data
        for org in organizations:
            # Apply Organisation configuration
            org_conf = {}
            org_conf = org_configuration(org)
            org_apps = []
            for app in applications:
                if app['organizationId'] == org['id']:
                    if in_scope(app=app):
                        org_apps.append(app_configuration(app))
            if len(org_apps) or in_scope(org=org):
                org_conf['Applications'] = org_apps
                od = {}
                od['Organizations'] = []
                od['Organizations'].append(org_conf)
                if (org_conf['Name'] == 'Root Organization'):
                    orgs.insert(0, org_conf)
                else:
                    orgs.append(org_conf)
                persist_data(od, f'{output_dir}{get_organization_name(org["id"])}-Healthcheck.json')

        data['Organizations'] = orgs
        if in_scope(None):
            persist_data(data, f'{output_dir}All-Organizations-Healthcheck.json')


def item_count(data=None, single=False):
    if data is None:
        return 0
    elif single is True:
        return 1
    return len(data)


def purge_empty_attributes(data):
    data2 = deepcopy(data)
    for attr in data:
        if data2[attr] is None:
            data2.pop(attr)
    return data2


def nexus_administration():

    systemConf = {}
    # Parses and applies all the 'administrative' configuration for Nexus IQ
    systemConf['users'] = persist_users()
    systemConf['custom_roles'] = persist_roles()
    systemConf['ldap_connections'] = persist_ldap_instances()
    systemConf['email_server'] = persist_email_server_connection()
    systemConf['proxy'] = persist_proxy()
    systemConf['webhooks'] = persist_webhooks()
    # systemConf['system_notice'] = persist_system_notice()
    systemConf['success_metrics'] = persist_success_metrics()
    systemConf['automatic_applications'] = persist_auto_applications()
    systemConf['automatic_source_control'] = persist_automatic_source_control()
    systemConf['success_metrics_reports'] = persist_success_metrics_reports()
    persist_data(systemConf, f'{output_dir}System-Healthcheck.json')


def org_configuration(org):
    orgconf = {}
    # Parses and applies all of the child Org configuration
    orgconf['Grandfathering'] = persist_grandfathering(org=org['id'])
    orgconf['Continuous Monitoring'] = persist_continuous_monitoring(org=org['id'])
    orgconf['Source Control'] = persist_source_control(org=org['id'])
    orgconf['Data Purging'] = persist_data_purging(org=org['id'])
    orgconf['Proprietary Components'] = persist_proprietary_components(org=org['id'])
    orgconf['Application Categories'] = persist_application_categories(org=org['id'])
    orgconf['Component Labels'] = persist_component_labels(org=org['id'])
    orgconf['License Threat Groups'] = persist_license_threat_groups(org=org['id'])
    orgconf['Access'] = persist_access(org=org['id'])
    orgconf['Policy'] = persist_policy(org=org['id'])
    orgconf['Name'] = org['name']
    return purge_empty_attributes(orgconf)


def app_configuration(app):

    app_conf = {}
    # Parses and applies all of the application configuration
    app_conf['Name'] = app['name']
    app_conf['Grandfathering'] = persist_grandfathering(app=app['publicId'])
    app_conf['Continuous Monitoring'] = persist_continuous_monitoring(app=app['publicId'])
    app_conf['Proprietary Components'] = persist_proprietary_components(app=app)
    app_conf['Component Labels'] = persist_component_labels(app=app['publicId'])
    app_conf['Source Control'] = persist_source_control(app=app['id'])
    app_conf['Public Id'] = app['publicId']
    app_conf['Application Tags'] = check_categories(app['applicationTags'])
    app_conf['Access'] = persist_access(app=app['id'])
    app_conf['Policy'] = persist_policy(app=app['id'])
    return purge_empty_attributes(app_conf)


def print_debug(c):
    # testing json output to console
    if debug and c is not None:
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


def put_url(url, params, root=""):
    # common put call
    resp = iq_session.put(url, json=params, auth=iq_auth, verify=not self_signed)
    return handle_resp(resp, root)


def org_or_app(org, app):
    if app:
        return f'application/{app}'
    if org is None:
        org = 'ROOT_ORGANIZATION_ID'
    return f'organization/{org}'


# --------------------------------------------------------------------------
def in_scope(app=None, org=None):
    if app is not None:
        return get_organization_name(app["organizationId"]) in entities or \
               app['publicId'] in entities or \
               "all" in entities
    if org is not None:
        return org['name'] in entities or \
               "all" in entities
    return "all" in entities


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


def get_organization_name(id):
    ret = None
    for org in organizations:
        if id in org['id']:
            ret = org['name']
            break
    return ret


def check_categories(app_tags):
    # If the application category does not exist, it will be added to the root organisation by default, by design.
    ret = []
    for tag in app_tags:
        tag_ = check_category(tag)
        if tag_ is not None:
            ret.append(tag_)
    if len(ret):
        return ret
    return None


def check_category(ac):
    ret = ''
    if len(ac) == 0:
        return None
    for c in categories:
        if ac['tagId'] == c['id']:
            ret = c['name']
            break
    if len(ret) > 0:
        return {'name': ret}
    return None


def persist_access(org='ROOT_ORGANIZATION_ID', app=None):
    if app is not None:
        url = f'{iq_url}/api/v2/roleMemberships/application/{app}'
        eid = app
    else:
        url = f'{iq_url}/api/v2/roleMemberships/organization/{org}'
        eid = org

    members = get_url(url)
    if members is not None:
        accessData = []
        for member in members['memberMappings']:
            role = member['roleId']
            for mem in member['members']:
                if mem['ownerId'] == eid:
                    accessData.append(f'{mem["userOrGroupName"]} has {roles[role]} role.')
        if len(accessData):
            return accessData
    return None


def persist_auto_applications():
    url = f'{iq_url}/rest/config/automaticApplications'
    data = get_url(url)
    return f'Automatic Application Enabled : {data["enabled"]}'


def persist_grandfathering(org='ROOT_ORGANIZATION_ID', app=None):

    url = f'{iq_url}/rest/policyViolationGrandfathering/{org_or_app(org, app)}'
    data = purge_empty_attributes(get_url(url))
    if data is not None:
        gfData = []
        try:
            if data["inheritedFromOrganizationName"] is not None:
                gfData.append(f'Is inherited from {data["inheritedFromOrganizationName"]}')
        except KeyError:
            if data["enabled"] is True: gfData.append(f'Is enabled')
            if data["allowChange"] is True: gfData.append(f'May be changed')

        if data["allowOverride"] is True: gfData.append(f'May be overridden')
        if len(gfData):
            return gfData
    return None


def persist_webhooks():
    url = f'{iq_url}/rest/config/webhook'
    return f'Webhooks : {item_count(get_url(url))}'


def persist_proxy():
    # This API applies the config regardless of whether the proxy is already configured.
    url = f'{iq_url}/api/v2/config/httpProxyServer'
    return f'Proxy Servers : {item_count(get_url(url), True)}'


def persist_source_control(org='ROOT_ORGANIZATION_ID', app=None):
    url = f'{iq_url}/api/v2/sourceControl/{org_or_app(org, app)}'
    # This API applies the config regardless of whether the proxy is already configured.
    data = get_url(url)
    if data is not None:
        scData = []
        if data is None:
            scData.append('SCM inherited')
        else:
            data.pop('token')
            data.pop('id')
            data.pop('ownerId')
            scData.append(purge_empty_attributes(data))
        return scData
    return None


def persist_policy(org='ROOT_ORGANIZATION_ID', app=None):
    if app is not None:
        # app level policy import/export is not supported
        return
    url = f'{iq_url}/rest/policy/{org_or_app(org, app)}/export'
    data = get_url(url)
    policyData = []
    if data is not None:
        for policy in data['policies']:
            policyData.append(f'Policy: {policy["name"]}')
        if len(policyData):
            return policyData
    return None


def persist_success_metrics():
    url = f'{iq_url}/rest/successMetrics'
    # This API applies the config regardless of whether the proxy is already configured.
    return f'Success Metrics Enabled : {get_url(url)["enabled"]}'


def persist_success_metrics_reports():
    url = f'{iq_url}/rest/successMetrics/report'
    return f'Success Metrics Reports : {item_count(get_url(url))}'


def persist_automatic_source_control():
    url = f'{iq_url}/rest/config/automaticScmConfiguration'
    return f'Automatic SCM Enabled : {get_url(url)["enabled"]}'


def persist_proprietary_components(org='ROOT_ORGANIZATION_ID', app=None):
    # This API applies the config regardless of whether the proxy is already configured.

    if app is not None:
        url = f'{iq_url}/rest/proprietary/application/{app["publicId"]}'
        eid = app['id']
    else:
        url = f'{iq_url}/rest/proprietary/organization/{org}'
        eid = org

    pcs = get_url(url)
    pcs = pcs['proprietaryConfigByOwners']
    if pcs is not None:
        pcsData = []
        for pc in pcs:
            data = pc['proprietaryConfig']
            if data['ownerId'] == eid:
                if len(data['packages']):
                    pcsData.append(f'Packages : {data["packages"]}.')
                if len(data['regexes']):
                    pcsData.append(f'Regexes : {data["regexes"]}.')
        if len(pcsData):
            return pcsData
    return None


def persist_roles():
    url = f'{iq_url}/rest/security/roles'
    data = get_url(url)
    count = 0
    for element in data:
        if element.pop('builtIn') is False:
            count = count + 1
    # persist_data(data, '{output_dir}system_roles.json')
    return f'Custom Roles : {count} '


def persist_continuous_monitoring(org='ROOT_ORGANIZATION_ID', app=None):
    url = f'{iq_url}/rest/policyMonitoring/{org_or_app(org, app)}'
    data = get_url(url)
    if data is not None:
        cmData = []
        cmData.append(f'CM Stage is {data["stageTypeId"]}')
        return cmData
    return None


def persist_data_purging(org='ROOT_ORGANIZATION_ID'):
    url = f'{iq_url}/api/v2/dataRetentionPolicies/organizations/{org}'
    data = get_url(url)
    if data is not None:
        arStages = deepcopy(data['applicationReports']['stages'])
        dpData = []
        for stage in arStages:
            if arStages[stage]['inheritPolicy'] is False:
                if arStages[stage]['enablePurging'] is False:
                    dpData.append(f'{stage} has no data purging.')
                else:
                    dpData.append(f'{stage} purges data every {arStages[stage]["maxAge"]}')
        if len(dpData):
            return dpData
    return None


def persist_application_categories(org='ROOT_ORGANIZATION_ID'):
    url = f'{iq_url}/api/v2/applicationCategories/organization/{org}'
    data = get_url(url)
    if data is not None:
        acData = []
        for ac in data:
            acData.append(f'{ac["name"]} - {ac["description"]}.')
        return acData
    return None


def persist_component_labels(org='ROOT_ORGANIZATION_ID', app=None):
    url = f'{iq_url}/api/v2/labels/{org_or_app(org, app)}'
    data = get_url(url)
    if data is not None:
        clData = []
        for label in data:
            clData.append(f'{label["label"]} - {label["description"]}')
        return clData
    return None


def persist_license_threat_groups(org='ROOT_ORGANIZATION_ID'):
    url = f'{iq_url}/rest/licenseThreatGroup/organization/{org}'
    data = get_url(url)
    if data is not None:
        ltgData = []
        for ltg in data:
            ltgData.append(f'{ltg["name"]} has threat level of {ltg["threatLevel"]}')
        return ltgData
    return None


def persist_ldap_instances():
    url = f'{iq_url}/rest/config/ldap'
    return f'LDAP connections : {item_count(get_url(url))}'


def persist_email_server_connection():
    url = f'{iq_url}/api/v2/config/mail'
    return f'Email Servers : {item_count(get_url(url), True)}'


def persist_users():
    url = f'{iq_url}/rest/user'
    return f'Local Users : {item_count(get_url(url), True)}'


def set_roles():
    global roles
    url = f'{iq_url}/api/v2/applications/roles'
    data = get_url(url)
    for role in data['roles']:
        roles[role['id']] = role['name']


# Write the data to a file...
def persist_data(data, filename):
    with open(filename, 'w') as outfile:
        json.dump(data, outfile, indent=2)
    print(f'Persisted data to {filename}')


# --------------------------------------------------------------------
if __name__ == "__main__":
    main()
