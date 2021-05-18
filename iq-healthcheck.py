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

from deepdiff import DeepDiff
import requests
import os

from requests.packages.urllib3.exceptions import InsecureRequestWarning
from copy import deepcopy

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
iq_session = requests.Session
iq_url, iq_auth, output_dir, debug = "", "", "", False
categories, organizations, template_organizations, applications, ldap_connections, entities = [], [], [], [], [], []
roleType = ['USER', 'GROUP']
roles = {}
self_signed = False
ROOT_ORG_NAME = 'Root Organization'


def get_arguments():
    global iq_url, iq_session, iq_auth, output_dir, debug, self_signed, entities, template_file
    parser = argparse.ArgumentParser(description="This script enables you to persist the configuration of IQ Server to JSON\
     data, thus supporting the config-as-code requirement of Sonatype customers")
    parser.add_argument('-u', '--url', help='', default="http://localhost:8070", required=False)
    parser.add_argument('-a', '--auth', help='', default="admin:admin123", required=False)
    parser.add_argument('-o', '--output', default="./healthcheck", required=False)
    parser.add_argument('-d', '--debug', default=False, required=False)
    parser.add_argument('-s', '--self_signed', default=False, required=False)
    parser.add_argument('-y', '--scope', default="all", required=False)
    parser.add_argument('-t', '--template', default=False, required=True)

    args = vars(parser.parse_args())
    iq_url = args["url"]
    credentials = args["auth"].split(":")
    output_dir = args["output"]
    if output_dir[-1] != '/':
        output_dir += '/'

    debug = args["debug"]
    self_signed = args["self_signed"]
    entities = args["scope"].split(",")
    template_file = args["template"]
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
        os.makedirs(output_dir, 0o755)
    except FileExistsError:
        if os.access(output_dir, os.W_OK) is False:
            print(f"Directory {output_dir} is not writeable!")
            return

    # store current applications, categories, and organizations
    set_categories()
    set_organizations()
    set_template_organizations(template_file)
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
            template = resolve_template_org(org['name'])
            org_conf = org_configuration(org, template)
            org_apps = []
            for app in applications:
                if app['organizationId'] == org['id']:
                    if in_scope(app=app):
                        app = app_configuration(app, resolve_template_app(template, app['name']))
                        if app is not None:
                            org_apps.append(app)
            if len(org_apps) or in_scope(org=org):
                try:
                    od = {'Organizations': []}
                    org_conf['Applications'] = org_apps
                    od['Organizations'].append(org_conf)
                    if org_conf['Name'] == ROOT_ORG_NAME:
                        orgs.insert(0, org_conf)
                    else:
                        orgs.append(org_conf)
                    persist_data(od, f'{output_dir}{get_organization_name(org["id"])}-Healthcheck.json')
                except TypeError:
                    pass

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
    systemConf = {'Users': persist_users(), 'Custom Roles': persist_roles(),
                  'LDAP Connections': persist_ldap_instances(), 'Email Server': persist_email_server_connection(),
                  'Proxy': persist_proxy(), 'Webhooks': persist_webhooks(),
                  'Success Metrics': persist_success_metrics(), 'Automatic Applications': persist_auto_applications(),
                  'Automatic Source Control': persist_automatic_source_control(),
                  'Success Metrics Reports': persist_success_metrics_reports()}
    # Parses and applies all the 'administrative' configuration for Nexus IQ
    # systemConf['system_notice'] = persist_system_notice()
    persist_data(purge_empty_attributes(systemConf), f'{output_dir}System-Healthcheck.json')


def resolve_template_org(org_name):
    template = None
    for torg in template_organizations:
        if torg['name'] == 'Template-Org':
            template = torg
        if torg['name'] == org_name:
            return torg
    return template


def resolve_template_app(template, app_name):
    if template is None:
        return None

    for tapp in template["applications"]:
        if tapp['name'] == 'Template-App':
            template = tapp
        if tapp['name'] == app_name:
            return tapp
    return template


def org_configuration(org, template):
    if template is None:
        print(f"Cannot perform health check for {org['name']} because there is no org of that name or Template-Org "
              f"within your template file - {template_file} ")
        return None
    orgconf = {'Name': org['name'],
               'Grandfathering': persist_grandfathering(template["grandfathering"], org=org),
               'Continuous Monitoring': persist_continuous_monitoring(template["continuous_monitoring_stage"], org=org),
               'Source Control': persist_source_control(template["source_control"], org=org),
               'Data Purging': persist_data_purging(template["data_purging"], org=org['id']),
               'Proprietary Components': persist_proprietary_components(template["proprietary_components"], org=org),
               'Application Categories': persist_application_categories(template["application_categories"], org),
               'Component Labels': persist_component_labels(template["component_labels"], org=org),
               'License Threat Groups': persist_license_threat_groups(template["license_threat_groups"], org),
               'Access': persist_access(template["access"], org=org),
               'Policy': persist_policy(template["policy"]["policies"], org=org)}

    def org_or_app_id(org, app):
        if app is not None and app["publicId"]:
            return f'application/{app["publicId"]}'
        if org is None:
            org = 'ROOT_ORGANIZATION_ID'
        return f'organization/{org["id"]}'
    # Parses and applies all of the child Org configuration
    return purge_empty_attributes(orgconf)


def app_configuration(app, template):
    if template is None:
        print(f"Cannot perform health check for {app['name']} because there is no app of that name or Template-App "
              f"within {template_file} ")
        return None
    app_conf = {'Name': app['name'],
                'Public Id': app['publicId'],
                'Grandfathering': persist_grandfathering(template["grandfathering"], app=app),
                'Continuous Monitoring': persist_continuous_monitoring(template["continuous_monitoring_stage"], app=app),
                'Proprietary Components': persist_proprietary_components(template["proprietary_components"], app=app),
                'Component Labels': persist_component_labels(template["component_labels"], app=app),
                'Source Control': persist_source_control(template["source_control"], app=app),
                'Application Tags': check_categories(template['applicationTags'], app),
                'Access': persist_access(template["access"], app=app),
                'Policy': persist_policy(template["policy"], app=app)}
    # Parses and applies all of the application configuration
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
    if app is not None and app["publicId"]:
        return f'application/{app["publicId"]}'
    if org is None:
        org = 'ROOT_ORGANIZATION_ID'
    return f'organization/{org["id"]}'


def org_or_app_id(org, app):
    if app is not None and app["id"]:
        return f'application/{app["id"]}'
    if org is None:
        org = 'ROOT_ORGANIZATION_ID'
    return f'organization/{org["id"]}'


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


def set_template_organizations(template):
    # Load the template data against which configuration health will be benchmarked.
    global template_organizations
    with open(template) as json_file:
        template_organizations = json.load(json_file)["organizations"]


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


def check_categories(template, app):
    # If the application category does not exist, it will be added to the root organisation by default, by design.
    ret = []
    applied_tags = []
    for tag in app["applicationTags"]:
        tag_ = check_category(tag)
        try:
            template.index(tag_)
            applied_tags.append(tag_)
        except (ValueError, AttributeError):
            ret.append(f'Application tag {tag_} should be removed from {app["name"]}')

    if template is not None:
        for tag in template:
            try:
                applied_tags.index(tag)
            except ValueError:
                ret.append(f'Application tag {tag} should be added to {app["name"]}')

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


def persist_access(template, org=None, app=None):
    if app is not None:
        url = f'{iq_url}/api/v2/roleMemberships/application/{app["id"]}'
        eid = app["id"]
        entity_name = app["name"]
    else:
        url = f'{iq_url}/api/v2/roleMemberships/organization/{org["id"]}'
        eid = org["id"]
        entity_name = org["name"]

    data = get_url(url)
    if data == template:
        return None
    if data is not None:
        accessData = []
        access = []
        # Iterate over the roles
        for member in data['memberMappings']:
            role = member['roleId']
            for mem in member['members']:
                # If the owner is scoped to the current org/app
                if mem['ownerId'] == eid:
                    access.append({})
                    # Add the role to the list of access controls for the current org/app
                    i = len(access)-1
                    access[i]["role"] = roles[role]
                    access[i]["user_or_group_name"] = mem['userOrGroupName']
                    access[i]["role_type"] = mem['type']
                    # Check the current org/app access against the template
                    try:
                        template.index(access[i])
                    except (ValueError, AttributeError):
                        # It should not be in the org/app if its not in the template!
                        accessData.append(f'Access {access[i]} should be removed from {entity_name}')

        # Iterate over the accessors in the template checking they exist within the current org/app
        try:
            for taccess in template:
                try:
                    access.index(taccess)
                except (ValueError, AttributeError):
                    # It should be in the org/app if its in the template!
                    accessData.append(f'Access {taccess} should be added to {entity_name}')
        except TypeError:
            pass

    if len(accessData):
        return accessData
    return None


def persist_auto_applications():
    url = f'{iq_url}/rest/config/automaticApplications'
    if get_url(url)["enabled"]:
        return f'Automatic application creation enabled.'
    return f'Automatic application creation disabled.'


def persist_grandfathering(template, org=None, app=None):
    url = f'{iq_url}/rest/policyViolationGrandfathering/{org_or_app(org, app)}'
    data = purge_empty_attributes(get_url(url))

    # The API does not return this for the root organization.
    try:
        data["inheritedFromOrganizationName"]
    except KeyError:
        template.pop("inheritedFromOrganizationName")

    if data == template:
        return None
    if app is not None:
        entity_name = app["name"]
    else:
        entity_name = org["name"]

    gf_data = f'Grandfathering should be configured: {template} for {entity_name}.'
    return gf_data


def persist_webhooks():
    url = f'{iq_url}/rest/config/webhook'
    wh = item_count(get_url(url), True)
    if wh:
        return f'{wh} Webhooks.'
    return None


def persist_proxy():
    # This API applies the config regardless of whether the proxy is already configured.
    url = f'{iq_url}/api/v2/config/httpProxyServer'
    ps = item_count(get_url(url), True)
    if ps:
        return f'Proxy server.'
    return None


def persist_source_control(template, org=None, app=None):
    url = f'{iq_url}/api/v2/sourceControl/{org_or_app_id(org, app)}'
    # This API applies the config regardless of whether the proxy is already configured.
    data = get_url(url)
    if app is not None:
        entity_name = app["name"]
    else:
        entity_name = org["name"]

    if data is None:
        print(f'{entity_name} does not have source control integration configured.')
        return None

    data.pop('id')
    data.pop('ownerId')
    full_template = deepcopy(template)
    if data["repositoryUrl"] is not None:
        data.pop("repositoryUrl")
        try:
            template.pop("repositoryUrl")
        except (KeyError, AttributeError):
            pass

    if data == template:
        return None

    data.pop('enableStatusChecks')
    for attr in data:
        if data[attr] is not None:
            if template is None:
                return (f'Source control should be inherited for {entity_name}.')
            else:
                return (f'Source control should be configured:  {full_template} for {entity_name}.')
    return None


def persist_policy(template, org=None, app=None):
    if app is not None:
        # app level policy import/export is not supported
        return

    if app is not None:
        entity_name = app["name"]
    else:
        entity_name = org["name"]

    url = f'{iq_url}/rest/policy/{org_or_app(org, app)}/export'
    data = get_url(url)['policies']
    policyData = []
    if data is not None:
        for policy in data:
            try:
                policy.pop('id')
                for constraint in policy['constraints']:
                    constraint.pop('id')
                template.index(policy)
            except ValueError:
                policyData.append(f'Policy: {policy} should be removed from {entity_name}')
        if template is not None:
            for policy in template:
                try:
                    data.index(policy)
                except (ValueError, AttributeError):
                    policyData.append(f'Policy: {policy} should be added to {entity_name}.')

    if len(policyData):
        return policyData
    return None


def persist_success_metrics():
    url = f'{iq_url}/rest/successMetrics'
    # This API applies the config regardless of whether the proxy is already configured.
    if get_url(url)["enabled"]:
        return f'Success metrics enabled.'
    return f'Success metrics disabled.'

def persist_success_metrics_reports():
    url = f'{iq_url}/rest/successMetrics/report'
    return f'{item_count(get_url(url))} Success metrics reports.'


def persist_automatic_source_control():
    url = f'{iq_url}/rest/config/automaticScmConfiguration'
    if get_url(url)["enabled"]:
        return f'Automatic SCM enabled.'
    return f'Automatic SCM disabled.'


def persist_proprietary_components(template, org=None, app=None):
    # This API applies the config regardless of whether the proxy is already configured.

    if app is not None:
        url = f'{iq_url}/rest/proprietary/application/{app["publicId"]}'
        eid = app['id']
        entity_name = app['name']
    else:
        url = f'{iq_url}/rest/proprietary/organization/{org["id"]}'
        eid = org["id"]
        entity_name = org['name']

    pcs = get_url(url)
    pcs = pcs['proprietaryConfigByOwners']
    if pcs == template:
        return None

    if pcs is not None:
        pcsData = []
        pcsx = []

        for pc in pcs:
            data = pc['proprietaryConfig']
            if data['ownerId'] == eid:
                if not (len(data['packages']) or len(data['regexes'])):
                    continue
                data['id'] = None
                data.pop('ownerId')
                pcsx.append(data)
                try:
                    template.index(data)
                except (ValueError, AttributeError):
                    pcsData.append(f'Proprietary component {data} should be removed from {entity_name}')

    if template is not None:
        for tpc in template:
            try:
                if not (len(tpc['packages']) or len(tpc['regexes'])):
                    continue
                pcsx.index(tpc)
            except (ValueError, AttributeError):
                pcsData.append(f'Proprietary component {tpc} should be added to {entity_name}')

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
    if count:
        return f'{count} Customer roles.'
    return None


def persist_continuous_monitoring(template, org=None, app=None):
    url = f'{iq_url}/rest/policyMonitoring/{org_or_app(org, app)}'
    data = get_url(url)
    if data is None:
        return None
    if app is not None:
        entity_name = app["name"]
    else:
        entity_name = org["name"]

    data.pop('id')
    data.pop('ownerId')
    if template == data:
        return None

    if template is not None:
        return f'Continuous monitoring should be configured: {template} for {entity_name}.'
    else:
        return f'Continuous monitoring should be inherited for {entity_name}.'


def persist_data_purging(template, org='ROOT_ORGANIZATION_ID'):
    url = f'{iq_url}/api/v2/dataRetentionPolicies/organizations/{org}'
    data = get_url(url)
    if data == template:
        return None
    if data is not None:
        arStages = deepcopy(data['applicationReports']['stages'])
        template_arStages = template["applicationReports"]["stages"]
        dpData = []
        org_name = get_organization_name(org)
        if arStages != template_arStages:
            for stage in arStages:
                if arStages[stage] != template_arStages[stage]:
                    dpData.append(f'Data purging for application reports {stage} stage should be: {template_arStages[stage]} for {org_name}')

        sm = deepcopy(data['successMetrics'])
        template_sm = template["successMetrics"]
        if sm != template_sm:
            dpData.append(f'Data purging for success metrics should be: {template_sm} for {org_name}')
        if len(dpData):
            return dpData
    return None


def persist_application_categories(template, org):
    url = f'{iq_url}/api/v2/applicationCategories/organization/{org["id"]}'
    data = get_url(url)
    if data == template:
        return None
    acData = []
    org_name = org['name']
    if data is not None:
        for ac in data:
            try:
                ac.pop("id")
                ac.pop("organizationId")
                template.index(ac)
            except (ValueError, AttributeError):
                acData.append(f'Application Category {ac} should be removed from {org_name}.')
    if template is not None:
        for ac in template:
            try:
                data.index(ac)
            except (ValueError, AttributeError):
                acData.append(f'Application Category {ac} should be added to {org_name}.')
    if len(acData):
        return acData
    return None

def persist_component_labels(template, org=None, app=None):
    url = f'{iq_url}/api/v2/labels/{org_or_app(org, app)}'
    data = get_url(url)
    if data == template:
        return None
    if app is not None:
        entity_name = app["name"]
    else:
        entity_name = org["name"]

    cl_data = []
    if data is not None:
        for cl in data:
            try:
                cl.pop("id")
                cl.pop("ownerId")
                template.index(cl)
            except (ValueError, AttributeError):
                cl_data.append(f'Component label {cl} should be removed from {entity_name}.')
    if template is not None:
        for cl in template:
            try:
                data.index(cl)
            except (ValueError, AttributeError):
                cl_data.append(f'Component label {cl} should be added to {entity_name}.')
    if len(cl_data):
        return cl_data
    return None


def persist_license_threat_groups(template, org):
    url = f'{iq_url}/rest/licenseThreatGroup/organization/{org["id"]}'
    data = get_url(url)
    if data == template:
        return None
    ltg_data = []
    org_name = org['name']
    if data is not None:
        for ltg in data:
            ltg.pop("id")
            ltg.pop("ownerId")
            ltg.pop("nameLowercaseNoWhitespace")
    if template is not None:
        for ltg in template:
            try:
                ltg.pop("licenses")
            except KeyError:
                pass
    if data is not None:
        for ltg in data:
            try:
                template.index(ltg)
            except (ValueError, AttributeError):
                ltg_data.append(f'License threat group {ltg} should be removed from {org_name}.')
    if template is not None:
        for ltg in template:
            try:
                data.index(ltg)
            except (ValueError, AttributeError):
                ltg_data.append(f'License threat group {ltg} should be added to {org_name}.')
    if len(ltg_data):
        return ltg_data
    return None


    if data is not None:
        ltgData = []
        for ltg in data:
            ltgData.append(f'{ltg["name"]} has threat level of {ltg["threatLevel"]}')
        return ltgData
    return None


def persist_ldap_instances():
    url = f'{iq_url}/rest/config/ldap'
    lc = item_count(get_url(url))
    return f'{lc} LDAP server(s).'


def persist_email_server_connection():
    url = f'{iq_url}/api/v2/config/mail'
    es = item_count(get_url(url), True)
    return f'{es} Email server.'


def persist_users():
    url = f'{iq_url}/rest/user'
    uc = item_count(get_url(url))
    return f'{uc} local users.'


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
