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
app_categories, organizations, template_organizations, applications, ldap_connections, entities = [], [], [], [], [], []
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
    set_app_categories()
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
                    validate_data(od, f'{output_dir}{get_organization_name(org["id"])}-Healthcheck.json')
                except TypeError:
                    pass

        data['Organizations'] = orgs
        if in_scope(None):
            validate_data(data, f'{output_dir}All-Organizations-Healthcheck.json')


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
    systemConf = {'Users': validate_users(), 'Custom Roles': validate_roles(),
                  'LDAP Connections': validate_ldap_instances(), 'Email Server': validate_email_server_connection(),
                  'Proxy': validate_proxy(), 'Webhooks': validate_webhooks(),
                  'Success Metrics': validate_success_metrics(), 'Automatic Applications': validate_auto_applications(),
                  'Automatic Source Control': validate_automatic_source_control(),
                  'Success Metrics Reports': validate_success_metrics_reports()}
    # Parses and applies all the 'administrative' configuration for Nexus IQ
    # systemConf['system_notice'] = validate_system_notice()
    validate_data(purge_empty_attributes(systemConf), f'{output_dir}System-Healthcheck.json')


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

    set_app_categories(org['id'])

    orgconf = {'Name': org['name'],
               'Grandfathering': validate_grandfathering(template["grandfathering"], org=org),
               'Continuous Monitoring': validate_continuous_monitoring(template["continuous_monitoring_stage"], org=org),
               'Source Control': validate_source_control(template["source_control"], org=org),
               'Data Purging': validate_data_purging(template["data_purging"], org=org),
               'Proprietary Components': validate_proprietary_components(template["proprietary_components"], org=org),
               'Application Categories': validate_application_categories(template["application_categories"], org),
               'Component Labels': validate_component_labels(template["component_labels"], org=org),
               'License Threat Groups': validate_license_threat_groups(template["license_threat_groups"], org),
               'Access': validate_access(template["access"], org=org),
               'Policy': validate_policy(template["policy"]["policies"], org=org)}

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
                'Grandfathering': validate_grandfathering(template["grandfathering"], app=app),
                'Continuous Monitoring': validate_continuous_monitoring(template["continuous_monitoring_stage"], app=app),
                'Proprietary Components': validate_proprietary_components(template["proprietary_components"], app=app),
                'Component Labels': validate_component_labels(template["component_labels"], app=app),
                'Source Control': validate_source_control(template["source_control"], app=app),
                'Application Tags': validate_application_tags(template['applicationTags'], app),
                'Access': validate_access(template["access"], app=app),
                'Policy': validate_policy(template["policy"], app=app)}
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


def set_app_categories(org='ROOT_ORGANIZATION_ID'):
    global app_categories
    # using categories from root organization.
    url = f'{iq_url}/api/v2/applicationCategories/organization/{org}'
    try:
        app_categories += get_url(url)
    except TypeError:
        pass


def get_organization_name(id):
    ret = None
    for org in organizations:
        if id in org['id']:
            ret = org['name']
            break
    return ret


def validate_application_tags(template, app):
    # If the application category does not exist, it will be added to the root organisation by default, by design.
    ret = []
    applied_tags = []
    for tag in app["applicationTags"]:
        tag_ = check_app_category(tag)
        if tag_ is not None:
            # The regard here is that a tag has been applied. Tags speak to HOW the application is delivered
            # and can influence policies in scope.
            # ret.append(f"Application tag '{tag_['name']}' has been applied to '{app['name']}'")
            return None
            # try:
            #     applied_tags.append(tag_)
            #     template.index(tag_)
            # except (AttributeError, ValueError):
            #     ret.append(f"Application tag {tag_} should be removed from {app['name']}'")

    if template is not None:
        # If tags exist in the template, advise that one should be applied.
        if not len(ret):
            ret.append(f"Application '{app['name']}' should have an application tag applied.")
        # for tag in template:
        #     try:
        #         applied_tags.index(tag)
        #     except ValueError:
        #         ret.append(f"Application tag {tag} should be added to '{app['name']}'")

    if len(ret):
        return ret
    return None


def check_app_category(ac):
    ret = ''
    if len(ac) == 0:
        return None

    for c in app_categories:
        if ac['tagId'] == c['id']:
            ret = c['name']
            break
    if len(ret) > 0:
        return {'name': ret}
    return None


def difference(l1, l2):
    list = l1 + l2
    return [value for value in list if (value in l1) - (value in l2)]


def validate_access(template, org=None, app=None):
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
        taccess = []

        # Iterate over the roles
        for member in data['memberMappings']:
            role = member['roleId']
            for mem in member['members']:
                # If the owner is scoped to the current org/app
                if mem['ownerId'] == eid:
                    try:
                        # Just checking for the presence of the role. There might be N users/groups that fulfil it!
                        access.index(roles[role])
                    except ValueError:
                        access.append({})
                        # Add the role to the list of access controls for the current org/app
                        i = len(access)-1
                        access[i] = roles[role]

        if template is not None:
            for t in template:
                taccess.append(t["role"])

        # Find the difference between the fulfilled roes and the templated roles
        anomalies = difference(access, taccess)
        for a in anomalies:
            try:
                # If the anomaly exists in the fulfilled roles, it is in excess of the template.
                access.index(a)
                accessData.append(f'{a} role should be removed from {entity_name}')
            except ValueError:
                accessData.append(f'{a} role should be added to {entity_name}')

    if len(accessData):
        return accessData
    return None


def validate_auto_applications():
    url = f'{iq_url}/rest/config/automaticApplications'
    if get_url(url)["enabled"]:
        return f'Automatic application creation enabled.'
    return f'Automatic application creation disabled.'


def validate_grandfathering(template, org=None, app=None):
    url = f'{iq_url}/rest/policyViolationGrandfathering/{org_or_app(org, app)}'
    data = purge_empty_attributes(get_url(url))

    if data == template:
        return None

    if app is not None:
        entity_name = app["name"]
    else:
        entity_name = org["name"]

    try:
        # The API does not return this for the root organization.
        if data['inheritedFromOrganizationName'] == template['inheritedFromOrganizationName']:
            return None
    except KeyError:
        # Must be the root
        if entity_name == ROOT_ORG_NAME:
            template.pop("inheritedFromOrganizationName")
            if data == template:
                return None
            else:
                return f"Grandfathering should be {rendor_json(template, True)} enabled for '{entity_name}'."

    return f"Grandfathering should be inherited from '{template['inheritedFromOrganizationName']}' for '{entity_name}'."


def validate_webhooks():
    url = f'{iq_url}/rest/config/webhook'
    wh = item_count(get_url(url), True)
    if wh:
        return f'{wh} Webhooks.'
    return None


def validate_proxy():
    # This API applies the config regardless of whether the proxy is already configured.
    url = f'{iq_url}/api/v2/config/httpProxyServer'
    ps = item_count(get_url(url), True)
    if ps:
        return f'Proxy server.'
    return None


def validate_source_control(template, org=None, app=None):
    url = f'{iq_url}/api/v2/sourceControl/{org_or_app_id(org, app)}'
    # This API applies the config regardless of whether the proxy is already configured.
    data = get_url(url)

    if app is not None:
        entity_name = app["name"]
        error = f'SCM configuration URL should be set for {entity_name}'
    else:
        entity_name = org["name"]
        error = f'SCM configuration should be set for {entity_name}, aligned to {template} data'

    # Neither configured - So nothing to do!
    if data == template:
        return None

    if data is not None:
        # Source control is applied to the Org/App
        try:
            # The URL only pertains to the application config!
            # Remove the id's which are unique to the data
            data.pop('id')
            data.pop('ownerId')
            # This attribute value appears indeterminate. Removing it from the template:data comparison to come!
            data.pop('enableStatusChecks')
            # The URL can not be specific within the template
            data.pop('repositoryUrl')
        except (KeyError, AttributeError):
            pass

        # SCM applied, but no template?
        # If SCM inherits the purge will ensure zero length
        if template is None and len(purge_empty_attributes(data)):
            return f'Source control should be removed for {entity_name}.'

    if template is not None:
        try:
            # This attribute value appears indeterminate. Removing it from the template:data comparison to come!
            tcopy = deepcopy(template)
            tcopy.pop('repositoryUrl')
            tcopy.pop('enableStatusChecks')
        except (KeyError, AttributeError):
            # It doesn't! So report the need to do so.
            pass

        # if both exist, the data should now match the template
        if data != tcopy:
            # If not, the template config is applicable
            return error

    return None


def validate_policy(template, org=None, app=None):
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
        # Iterate over the entity policies
        for policy in data:
            try:
                # Remove the IDs so the policy can be compared for parity with the template policies
                policy.pop('id')
                for constraint in policy['constraints']:
                    constraint.pop('id')
                # Does the template contain the entity policy?
                template.index(policy)
            except ValueError:
                # No! Remove it.
                policyData.append(f'Policy: {policy} should be removed from {entity_name}')

        if template is not None:
            # Iterate over the template policies
            for policy in template:
                try:
                    # Does the entity data contain the template policy?
                    data.index(policy)
                except (ValueError, AttributeError):
                    # No! Add it.
                    policyData.append(f'Policy: {policy} should be added to {entity_name}.')

    if len(policyData):
        return policyData
    return None


def validate_success_metrics():
    url = f'{iq_url}/rest/successMetrics'
    # This API applies the config regardless of whether the proxy is already configured.
    if get_url(url)["enabled"]:
        return f'Success metrics enabled.'
    return f'Success metrics disabled.'

def validate_success_metrics_reports():
    url = f'{iq_url}/rest/successMetrics/report'
    return f'{item_count(get_url(url))} Success metrics reports.'


def validate_automatic_source_control():
    url = f'{iq_url}/rest/config/automaticScmConfiguration'
    if get_url(url)["enabled"]:
        return f'Automatic SCM enabled.'
    return f'Automatic SCM disabled.'


def validate_proprietary_components(template, org=None, app=None):
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

        # Iterate over the proprietary config items list
        for pc in pcs:
            data = pc['proprietaryConfig']
            # Only evaluate the PCs that are scoped to the current entity - list contains the inherited ones too!
            if data['ownerId'] == eid:
                # If the content is 'empty' ignore it
                if not (len(data['packages']) or len(data['regexes'])):
                    continue

                # Negate the IDs so the PC data can be compared for parity with the template
                data['id'] = None
                data.pop('ownerId')
                pcsx.append(data)
                try:
                    # Does the data align with the template content?
                    template.index(data)
                except (ValueError, AttributeError):
                    # No! Remove it from IQ.
                    pcsData.append(f'Proprietary component {rendor_json(purge_empty_attributes(data), True)} should '
                                   f'be removed from {entity_name}')

    # Iterate over the template PC data
    if template is not None:
        for tpc in template:
            try:
                # If the data is empty, move on!
                if not (len(tpc['packages']) or len(tpc['regexes'])):
                    continue
                # Does the template PC data align with the entity data
                pcsx.index(tpc)
            except (ValueError, AttributeError):
                # No! Add it.
                pcsData.append(f'Proprietary component {rendor_json(purge_empty_attributes(tpc), True)} should be added to {entity_name}')

    if len(pcsData):
        return pcsData
    return None


def validate_roles():
    url = f'{iq_url}/rest/security/roles'
    data = get_url(url)
    count = 0
    for element in data:
        if element.pop('builtIn') is False:
            count = count + 1
    if count:
        return f'{count} Customer roles.'
    return None


def validate_continuous_monitoring(template, org=None, app=None):
    url = f'{iq_url}/rest/policyMonitoring/{org_or_app(org, app)}'
    data = get_url(url)

    if app is not None:
        entity_name = app["name"]
    else:
        entity_name = org["name"]

    if data is not None:
        data.pop('id')
        data.pop('ownerId')

    if template == data:
        return None

    if template is None:
        return f'Continuous monitoring should be inherited for {entity_name}.'
    return f'Continuous monitoring stage should be the {rendor_json(template)} for {entity_name}.'


def validate_data_purging(template, org):
    url = f'{iq_url}/api/v2/dataRetentionPolicies/organizations/{org["id"]}'
    data = get_url(url)

    if data == template:
        return None
    if data is not None:
        arStages = deepcopy(data['applicationReports']['stages'])
        template_arStages = template["applicationReports"]["stages"]
        dpData = []
        org_name = org["name"]
        if arStages != template_arStages:
            for stage in arStages:
                if arStages[stage] != template_arStages[stage]:
                    if template_arStages[stage]['inheritPolicy']:
                        dpData.append(f'Data purging for application reports {stage} stage should be inherited for {org_name}')
                    elif org_name == ROOT_ORG_NAME:
                        # ROOT can't inherit!
                        td = deepcopy(template_arStages[stage])
                        td.pop('inheritPolicy')
                        dpData.append(f'Data purging for application reports {stage} stage should be: {td} for {org_name}')
                    else:
                        dpData.append(f'Data purging for application reports {stage} stage should be: {template_arStages[stage]} for {org_name}')

        sm = deepcopy(data['successMetrics'])
        template_sm = template["successMetrics"]
        if template_sm['inheritPolicy']:
            dpData.append(f'Data purging for application reports success metrics stage should be inherited for {org_name}')
        elif org_name == ROOT_ORG_NAME:
            # ROOT can't inherit!
            td = deepcopy(template_sm)
            td.pop('inheritPolicy')
            dpData.append(f'Data purging for application reports success metrics should be: {td} for {org_name}')
        else:
            dpData.append(f'Data purging for application reports success metrics should be: {template_sm} for {org_name}')

        # if sm != template_sm:
        #     dpData.append(f'Data purging for success metrics should be: {template_sm} for {org_name}')
        if len(dpData):
            return dpData
    return None


def validate_application_categories(template, org):
    url = f'{iq_url}/api/v2/applicationCategories/organization/{org["id"]}'
    data = get_url(url)
    if data == template:
        return None
    acData = []
    org_name = org['name']
    if data is not None:
        # Iterate over the ACs
        for ac in data:
            try:
                # Remove the IDs so the data can be compared for parity with the template AC data
                ac.pop("id")
                ac.pop("organizationId")
                # Does the AC exist in the template for the org?
                template.index(ac)
            except (ValueError, AttributeError):
                # No! Remove it.
                acData.append(f"Application Category '{ac}' should be removed from '{org_name}'.")

    if template is not None:
        # Iterate over the ACs in the template
        for ac in template:
            try:
                # Does the template AC exist in the data for the org?
                data.index(ac)
            except (ValueError, AttributeError):
                # No! Add it.
                acData.append(f"Application Category '{ac}' should be added to '{org_name}'.")
    if len(acData):
        return acData
    return None


def validate_component_labels(template, org=None, app=None):
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
        # Iterate over the CLs for the entity
        for cl in data:
            try:
                # Remove the IDs so the CL data can be compated for parity with the template data
                cl.pop("id")
                cl.pop("ownerId")
                # Does the CL exist in the template?
                template.index(cl)
            except (ValueError, AttributeError):
                # No! Remove it.
                cl_data.append(f"Component label '{cl['label']}' should be removed from '{entity_name}'.")

    if template is not None:
        # Iterate over the CL for the template
        for cl in template:
            try:
                # Does the template CL exist in the entity CL list?
                data.index(cl)
            except (ValueError, AttributeError):
                # No! Add it.
                cl_data.append(f"Component label '{cl['label']}' should be added to '{entity_name}'.")

    if len(cl_data):
        return cl_data
    return None


def validate_license_threat_groups(template, org):
    url = f'{iq_url}/rest/licenseThreatGroup/organization/{org["id"]}'
    data = get_url(url)
    if data == template:
        return None
    ltg_data = []
    org_name = org['name']

    if data is not None:
        # Iterate over the TGs in the org data
        for ltg in data:
            # Remove the attributes that will enable parity comparison with the template data
            ltg.pop("id")
            ltg.pop("ownerId")
            ltg.pop("nameLowercaseNoWhitespace")

    if template is not None:
        # Iterate over the template
        for ltg in template:
            try:
                # Remove the license association (likely to have come from a 'scrape' file being used as a template)
                ltg.pop("licenses")
            except KeyError:
                pass

    if data is not None:
        # Iterate over the LTGs in the Org data
        for ltg in data:
            try:
                # Does the LTG exist in the template?
                template.index(ltg)
            except (ValueError, AttributeError):
                # No! Remove it.
                ltg_data.append(f'License threat group {ltg} should be removed from {org_name}.')

    if template is not None:
        # Iterate over the LTGs in the template
        for ltg in template:
            try:
                # Does the LTG exist in the Org data
                data.index(ltg)
            except (ValueError, AttributeError):
                # No! Add it.
                ltg_data.append(f'License threat group {ltg} should be added to {org_name}.')

    if len(ltg_data):
        return ltg_data
    return None


def validate_ldap_instances():
    url = f'{iq_url}/rest/config/ldap'
    lc = item_count(get_url(url))
    return f'{lc} LDAP server(s).'


def validate_email_server_connection():
    url = f'{iq_url}/api/v2/config/mail'
    es = item_count(get_url(url), True)
    return f'{es} Email server.'


def validate_users():
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
def validate_data(data, filename):
    with open(filename, 'w') as outfile:
        json.dump(data, outfile, indent=2)
    print(f'Persisted data to {filename}')


def rendor_json(data, keys=False):
    text = ""
    if type(data) is dict:
        if keys:
            for d in data:
                text += f"'{d}:{data[d]}',"
        else:
            for d in data:
                text += f"'{data[d]}',"

    elif type(data) is list:
        for d in data:
            text += f"'{d}', "
    return text[:len(text)-1]

# --------------------------------------------------------------------
if __name__ == "__main__":
    main()
