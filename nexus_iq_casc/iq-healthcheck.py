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
import time

from requests.packages.urllib3.exceptions import InsecureRequestWarning
from copy import deepcopy

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
iq_session = requests.Session
iq_url, iq_auth, output_dir, debug = "", "", "", False
app_categories, organizations, template_organizations, applications, ldap_connections, entities = [], [], [], [], [], []
roleType = ['USER', 'GROUP']
roles = {}
webhooks = {}
self_signed = False
ROOT_ORG_NAME = 'Root Organization'
TEMPLATE_ORG_NAME = 'Template-Org'
TEMPLATE_APP_NAME = 'Template-App'
totalAdvisories = 0
Advisories = {
    'Users':'There are no local users.',
    'Custom Roles':'There are no custom roles.',
    'LDAP Connections':'There are no LDAP servers configured.',
    'Email Server':'There is no Email servers configured.',
    'Proxy':'There is no Proxy server configured.',
    'Webhooks':'There are no Webhooks configured.',
    'Success Metrics':'Success metrics are disabled.',
    'Success Metrics Reports':'There are no Success Metrics reports available.',
    'Automatic Applications':'Automatic application creation is disabled.',
    'Automatic Source Control':'Automatic Source Control Management is disabled.',
    'TOTAL NUMBER OF ADVISORIES':'There are '+str(totalAdvisories)+' active advisories currently.',
    'Grandfathering':'Grandfathering is configured correctly.',
    'ContinuousMonitoring':'Continuous Monitoring is not enabled.',
    'SCM':'Source Control Management has not been configured.',
    'DataPurging':'',
    'ProprietaryComponents':'',
    'AppCategories':'Default application categories are configured. No custom application categories in place.',
    'ComponentLabels':'',
    'LTGAdvisories':'',
    'AccessAdvisories':'',
    'PolicyAdvisories':'',
    'UserNotifications':'User notifications are not configured.',
    'RoleNotifications':'Role notifications are not configured.',
    'JiraNotifications':'Jira notifications are not configured.',
    'WebhookNotifications':'Webhook notifications are not configured.',
    'Tags':'Application tags are not being used.'
    }
policyAdvisories = []
proprietaryComps = []
dataPurging = []
appCategories = []
compLabels = []
ltgAdvisories = []
accessAdvisories = []
grandAdvisories = []
appTags = []
contMonitoring = []
SCMadvisories = []
notifs = {"User notifications": [], "Role notifications": [], "Jira notifications": [], "Webhook notifications": []}
notifsCounts = {"User notifications": 0, "Role notifications": 0, "Jira notifications": 0, "Webhook notifications": 0}
persistedMessages = []

#---------------------------------
#
# Print iterations progress
def printProgressBar (
        iteration,
        total,
        prefix = 'Progress:',
        suffix = 'Complete',
        decimals = 1,
        length = 50,
        fill = '█'):

    time.sleep(0.1)
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    print('\r%s |%s| %s%% %s' % (prefix, bar, percent, suffix), end = '\r')
    # Print New Line on Complete
    if iteration == total:
        print()

#---------------------------------

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
    # An errant '/' on the URL does not prevent a connection, but does scupper the REST calls working!
    if iq_url[len(iq_url)-1] == "/":
        iq_url = iq_url[:-1]
    credentials = args["auth"].split(":", 1)
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
    set_webhooks()

    #-----------------------------------------------------------------------------------
    #t,segments = 0, len(organizations)
    t,segments = 0, len(applications)
    #print(len(applications))
    printProgressBar(t,segments)
    #-----------------------------------------------------------------------------------

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
                        #-----------------------------------------------------------------------------------
                        t +=1
                        printProgressBar(t,segments)
                        #-----------------------------------------------------------------------------------
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

    Advisories.update({'PolicyAdvisories':'There are '+str(sum(policyAdvisories))+' advisories relating to policy disparities. Please check All-Organizations-Healthcheck.json for details.'})
    Advisories.update({'ProprietaryComponents':'There are '+str(sum(proprietaryComps))+' advisories relating to Proprietary Components. Please check All-Organizations-Healthcheck.json for details.'})
    Advisories.update({'DataPurging':'There are '+str(sum(dataPurging))+' advisories relating to Data Purging. Please check All-Organizations-Healthcheck.json for details.'})
    Advisories.update({'AppCategories':'There are '+str(sum(appCategories))+' advisories relating to Application Categories. Please check All-Organizations-Healthcheck.json for details.'})
    Advisories.update({'ComponentLabels':'There are '+str(sum(compLabels))+' advisories relating to Component Labels. Please check All-Organizations-Healthcheck.json for details.'})
    Advisories.update({'LTGAdvisories':'There are '+str(sum(ltgAdvisories))+' advisories relating to Licence Threat Groups. Please check All-Organizations-Healthcheck.json for details.'})
    Advisories.update({'AccessAdvisories':'There are '+str(sum(accessAdvisories))+' advisories relating to Access roles. Please check All-Organizations-Healthcheck.json for details.'})
    Advisories.update({'Grandfathering':'There are '+str(len(grandAdvisories))+' advisories relating to Grandfathering. Please check All-Organizations-Healthcheck.json for details.'})
    Advisories.update({'Tags':'There are '+str(sum(appTags))+' advisories relating to application tags. Please check All-Organizations-Healthcheck.json for details.'})
    Advisories.update({'ContinuousMonitoring':'There are '+str(len(contMonitoring))+' advisories relating to Continuous Monitoring. Please check All-Organizations-Healthcheck.json for details.'})
    Advisories.update({'SCM':'There are '+str(len(SCMadvisories))+' advisories relating to Source Control Management. Please check All-Organizations-Healthcheck.json for details.'})
    Advisories.update({'UserNotifications':'There are '+str(notifsCounts['User notifications'])+' advisories relating to User Notifications. Please check All-Organizations-Healthcheck.json for details.'})
    Advisories.update({'RoleNotifications':'There are '+str(notifsCounts['Role notifications'])+' advisories relating to Role Notifications. Please check All-Organizations-Healthcheck.json for details.'})
    Advisories.update({'JiraNotifications':'There are '+str(notifsCounts['Jira notifications'])+' advisories relating to Jira Notifications. Please check All-Organizations-Healthcheck.json for details.'})
    Advisories.update({'WebhookNotifications':'There are '+str(notifsCounts['Webhook notifications'])+' advisories relating to Webhook Notifications. Please check All-Organizations-Healthcheck.json for details.'})


    totalAdvisories = sum(policyAdvisories)+sum(proprietaryComps)+sum(dataPurging)+sum(appCategories)+sum(compLabels)+sum(ltgAdvisories)+sum(accessAdvisories)+len(grandAdvisories)+sum(appTags)+len(contMonitoring)+len(SCMadvisories)
    Advisories.update({'TOTAL NUMBER OF ADVISORIES':'There are '+str(totalAdvisories)+' active advisories currently. Please check All-Organizations-Healthcheck.json for details.'})

    extract_advisories()
    for message in range(0,len(persistedMessages)):
        print(persistedMessages[message])


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
    systemConf = {'Users': validate_users(), 'Custom Roles': validate_roles(), 'Administrators': validate_administrators(),
                  'LDAP Connections': validate_ldap_instances(), 'Email Server': validate_email_server_connection(),
                  'Proxy': validate_proxy(), 'Webhooks': validate_webhooks(),
                  'Success Metrics': validate_success_metrics(),
                  'Success Metrics Reports': validate_success_metrics_reports(),
                  'Automatic Applications': validate_auto_applications(),
                  'Automatic Source Control': validate_automatic_source_control(),
                  }
    # Parses and applies all the 'administrative' configuration for Nexus IQ
    # systemConf['system_notice'] = validate_system_notice()
    validate_data(purge_empty_attributes(systemConf), f'{output_dir}System-Healthcheck.json')

def extract_advisories():
    validate_data(Advisories, f'{output_dir}Advisories.json')

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
               'Proprietary Components': validate_proprietary_components(template, org=org),
               'Application Categories': validate_application_categories(template["application_categories"], org),
               'Component Labels': validate_component_labels(template["component_labels"], org=org),
               'License Threat Groups': validate_license_threat_groups(template["license_threat_groups"], org),
               'Access': validate_access(template["access"], org=org),
               'Policy': validate_policy(template["policy"], org=org)}

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
                'Proprietary Components': validate_proprietary_components(template, app=app),
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
        #print(resp.text)           ###
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
            try:
                applied_tags.append(tag_)
                template.index(tag_)
            except (AttributeError, ValueError):
                ret.append(f"Application tag '{tag_['name']}' should be removed from {app['name']}'")

    if template is not None:
        # If tags exist in the template, advise that one should be applied.
        index = -1
        for tag in template:
            try:
                index = applied_tags.index(tag)
                # One of the applied tags appears in the template. That is enough because the application has been
                # annotated to reflect how it is delivered
                break
            except ValueError:
                pass
        if index == -1:
            if len(template):
                ret.append(f"One of the following template application tags '{template}' should be applied to '{app['name']}'")

    if len(ret):
        appTags.append(len(ret))
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
        removes = 0
        adds = 0
        for a in anomalies:
            try:
                # If the anomaly exists in the fulfilled roles, it is in excess of the template.
                access.index(a)
                accessData.append(f'{a} role should be removed from {entity_name}')
                removes += 1
            except ValueError:
                accessData.append(f'{a} role should be added to {entity_name}')
                adds += 1
    if len(accessData):
        accessAdvisories.append(len(accessData))
        return accessData
    return None


def validate_auto_applications():
    url = f'{iq_url}/rest/config/automaticApplications'
    if get_url(url)["enabled"]:
        Advisories.update({'Automatic Applications':'Automatic application creation is enabled.'})
        return f'Automatic application creation enabled.'
    Advisories.update({'Automatic Applications':'Automatic application creation is disabled.'})
    return f'Automatic application creation disabled.'


def validate_grandfathering(template, org=None, app=None):
    url = f'{iq_url}/rest/policyViolationGrandfathering/{org_or_app(org, app)}'
    data = purge_empty_attributes(get_url(url))

    if data == template:
        return None
    if template == None:
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
                grandAdvisories.append(f"Grandfathering should be ["+f"{rendor_json(template, True)}"+f"] enabled for '{entity_name}'.")
                return f"Grandfathering should be {rendor_json(template, True)} enabled for '{entity_name}'."

    grandAdvisories.append(f"Grandfathering should be inherited from '{template['inheritedFromOrganizationName']}' for '{entity_name}'.")
    return f"Grandfathering should be inherited from '{template['inheritedFromOrganizationName']}' for '{entity_name}'."


def validate_webhooks():
    url = f'{iq_url}/rest/config/webhook'
    wh = item_count(get_url(url), True)
    if wh:
        Advisories.update({'Webhooks' : 'There are '+str(wh)+' Webhooks configured.'})
        return f'{wh} Webhooks.'
    return None


def validate_proxy():
    # This API applies the config regardless of whether the proxy is already configured.
    url = f'{iq_url}/api/v2/config/httpProxyServer'
    ps = item_count(get_url(url), True)
    Advisories.update({'Proxy' : 'There are no proxy servers configured.'})
    if ps:
        Advisories.update({'Proxy' : 'There are '+str(ps)+' proxy servers configured.'})
        return f'There are '+str(ps)+' proxy servers configured.'
    return f'There are no proxy servers configured.'


def validate_source_control(template, org=None, app=None):
    url = f'{iq_url}/api/v2/sourceControl/{org_or_app_id(org, app)}'
    # This API applies the config regardless of whether the proxy is already configured.
    data = get_url(url)

    if app is not None:
        entity_name = app["name"]
        error = f'SCM configuration URL should be set for {entity_name}.'
    else:
        entity_name = org["name"]
        error = f'SCM configuration should be set for {entity_name}, aligned to {template} data.'

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
            SCMadvisories.append(f'Source control should be removed for {entity_name}.')
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
            SCMadvisories.append(error)
            return error

    return None


def policy_notification_disparities(notifications, tnotifications, ntype, nkey, tnkey, names=None):
    if notifications != tnotifications:
        try:
            # Iterate over the notifications in the IQ policy checking for disparity between notifications
            # that exist in both template and IQ and notifications missing from the template.
            for notification in notifications:
                found = False
                if names:
                    lookup = names[notification[nkey]]
                else:
                    lookup = notification[nkey]

                # Iterate over the notifications required within the template
                for tnotification in tnotifications:
                    # Notifications for the same role?
                    if lookup == tnotification[tnkey]:
                        # If the notification stages match, we have a match. Happy days!
                        if set(notification['stageIds']) != set(tnotification['stageIds']):
                            notifs[ntype].append(f"{ntype} are mis-aligned for {difference(notification['stageIds'], tnotification['stageIds'])} between the policy and the template for the '{tnotification[tnkey]}'.")
                        # Alignment has been identified, so move on.
                        found = True
                        break
                if not found:
                    if not names:
                        notifs[ntype].append(f"Remove {ntype} set within Nexus for {notification[nkey]} that are not set within the template.")
                    else:
                        notifs[ntype].append(f"Remove {ntype} set within Nexus for {names[notification[nkey]]} that are not set within the template.")

            # Iterate over the template notifications looking for template notifications not present in IQ
            for tnotification in tnotifications:
                found = False
                # Iterate over the IQ notifications
                for notification in notifications:
                    if names:
                        lookup = names[notification[nkey]]
                    else:
                        lookup = notification[nkey]

                    # Notifications for the same role?
                    if tnotification[tnkey] == lookup:
                        found = True
                        # Any disparity is identified above, so the requirement here is to check only for missing notifications
                        break
                if not found:
                    notifs[ntype].append(f"Add {ntype} specified for {tnotification[tnkey]} in the template")

        except (TypeError, KeyError):
            notifs[ntype].append(f"{ntype} are not aligned between the policy and the template.")

        advisories = None
        if len(notifs[ntype]):
            advisories = deepcopy(notifs[ntype])
            notifsCounts[ntype] += len(advisories)
        notifs[ntype].clear()
        return advisories

    return None


def advise_policy_disparities(policy, tpolicy, policyAdvisories):
    policy_advisories = []
    name = policy['name']
    if policy['ownerId'] != tpolicy['ownerId']:
        policy_advisories.append(f'{name} belongs to {get_organization_name(policy["ownerId"])}, but should belong to {get_organization_name(tpolicy["ownerId"])}.')
    if policy['threatLevel'] != tpolicy['threatLevel']:
        policy_advisories.append(f'{name} has threat level {policy["threatLevel"]}, but should have threat level {tpolicy["threatLevel"]}.')
    if policy['policyViolationGrandfatheringAllowed'] != tpolicy['policyViolationGrandfatheringAllowed']:
        policy_advisories.append(f'{name} has Grandfathering set {policy["policyViolationGrandfatheringAllowed"]}, but should have it set {tpolicy["policyViolationGrandfatheringAllowed"]}.')

    # Remove the constraint id's to ensure comparison can work.
    for constraint in policy['constraints']:
        for condition in constraint['conditions']:
            condition.pop('value')
    for constraint in tpolicy['constraints']:
        for condition in constraint['conditions']:
            condition.pop('value')
    if policy['constraints'] != tpolicy['constraints']:
        policy_advisories.append(f'{name} policy constraints differ between the configuration in Nexus and that in the template.')

    if policy['actions'] != tpolicy['actions']:
        # Find actions in Nexus but not the template
        actions = {k: policy['actions'][k] for k in set(policy['actions']) - set(tpolicy['actions'])}
        for item in actions.items():
            policy_advisories.append(f'Remove \'{item[1]}\' action from the \'{item[0]}\' scan stage')
        # Find actions in the template but not Nexus
        actions = {k: tpolicy['actions'][k] for k in set(tpolicy['actions']) - set(policy['actions'])}
        for item in actions.items():
            policy_advisories.append(f'Add \'{item[1]}\' action to the \'{item[0]}\' scan stage')
        # Find actions that differ in Nexus and the template for the policy
        for item in policy['actions'].items():
            try:
                if policy['actions'][item[0]] != tpolicy['actions'][item[0]]:
                    policy_advisories.append(f'Amend \'{item[0]}\' action from {policy["actions"][item[0]]} to {tpolicy["actions"][item[0]]}')
            except KeyError:
                pass

    advisory = policy_notification_disparities(policy['notifications']['userNotifications'], tpolicy['notifications']['userNotifications'], 'User notifications', 'emailAddress', 'emailAddress')
    if advisory is not None:
        policy_advisories.append(advisory)
    advisory = policy_notification_disparities(policy['notifications']['roleNotifications'], tpolicy['notifications']['roleNotifications'], 'Role notifications', 'roleId', 'role', roles)
    if advisory is not None:
        policy_advisories.append(advisory)
    advisory = policy_notification_disparities(policy['notifications']['jiraNotifications'], tpolicy['notifications']['jiraNotifications'], 'Jira notifications', 'webhookId', 'webhook')
    if advisory is not None:
        policy_advisories.append(advisory)
    advisory = policy_notification_disparities(policy['notifications']['webhookNotifications'], tpolicy['notifications']['webhookNotifications'], 'Webhook notifications', 'webhookId', 'webhook', webhooks)
    if advisory is not None:
        policy_advisories.append(advisory)
    policyAdvisories.append(len(policy_advisories))
    #print(len(policy_advisories))
    return policy_advisories


def advise_policytag_disparities(policytag, tpolicytag):
    policy_advisories = []
    policy_advisories.append(f'Policy {policytag["policyName"]} uses incorrect `{policytag["tagName"]}` application category. Apply `{tpolicytag["tagName"]}` application category to align with templated best practice.')
    return policy_advisories


def validate_policy(template, org=None, app=None):
    if app is not None:
        # app level policy import/export is not supported
        return

    if app is not None:
        entity_name = app["name"]
    else:
        entity_name = org["name"]

    url = f'{iq_url}/rest/policy/{org_or_app(org, app)}/export'
    data = get_url(url)
    policyData = {}
    policy_lookup = {}

    if data['policies'] is not None:
        # Iterate over the entity policies
        for policy in data['policies']:
            try:
                # Remove the IDs so the policy can be compared for parity with the template policies
                policy_lookup[policy.pop('id')] = policy['name']
                for constraint in policy['constraints']:
                    constraint.pop('id')
                # Does the template contain the entity policy?
                # If the policy matches the template, so remove it from the template for disparity comparison
                del(template['policies'][template['policies'].index(policy)])
            except ValueError:
                # The template policy will be retained for disparity comparison and reporting
                pass

        if template['policies'] is not None:
            # Iterate over the template policies
            for tpolicy in template['policies']:
                # Does the entity data contain the template policy?
                for policy in data['policies']:
                    if policy['name'] == tpolicy['name']:
                        advisories = advise_policy_disparities(policy, tpolicy,policyAdvisories)
                        if len(advisories):
                            policyData[policy['name']] = advisories
                        break

    # Iterate over the policy tags in IQ and identify them in the template
    if data['policyTags'] is not None:
        ptags_anomolies = []
        for ptag_anomoly in data['policyTags']:
            try:
                tag = {}
                tag['policyName'] = policy_lookup[ptag_anomoly['policyId']]
                tag['tagName'] = check_app_category(ptag_anomoly)['name']

                # Does the template contain the entity policy?
                # If the policy matches the template, so remove it from the template for disparity comparison
                del(template['policyTags'][template['policyTags'].index(tag)])
            except ValueError:
                # The template policy will be retained for disparity comparison and reporting
                ptags_anomolies.append(tag)
                pass

        if template['policyTags'] is not None:
            # Iterate over the template policies
            for tptag in template['policyTags']:
                # Does the entity data contain the template policy?
                for ptag_anomoly in ptags_anomolies:
                    try:
                        if ptag_anomoly['policyName'] == tptag['policyName']:
                            advisories = advise_policytag_disparities(ptag_anomoly, tptag)
                            policyAdvisories.append(len(advisories))
                            if len(advisories):
                                policyData[f'{ptag_anomoly["policyName"]}-Application-Categories'] = advisories
                            break
                    except KeyError:
                        pass

    if len(policyData):
        #print(policyData)
        return policyData
    return None


def validate_success_metrics():
    url = f'{iq_url}/rest/successMetrics'
    # This API applies the config regardless of whether the proxy is already configured.
    if get_url(url)["enabled"]:
        Advisories.update({'Success Metrics':f'Success metrics are enabled.'})
        return f'Success metrics enabled.'
    Advisories.update({'Success Metrics':f'Success metrics are disabled.'})
    return f'Success metrics disabled.'

def validate_success_metrics_reports():
    url = f'{iq_url}/rest/successMetrics/report'
    Advisories.update({'Success Metrics Reports':f'There are {item_count(get_url(url))} Success metrics reports available.'})
    return f'{item_count(get_url(url))} Success metrics reports.'


def validate_automatic_source_control():
    url = f'{iq_url}/rest/config/automaticScmConfiguration'
    if get_url(url)["enabled"]:
        Advisories.update({'Automatic Source Control':f'Automatic Source Control Management is enabled.'})
        return f'Automatic SCM is enabled.'
    Advisories.update({'Automatic Source Control':f'Automatic Source Control Management is disabled.'})
    return f'Automatic SCM is disabled.'


def validate_proprietary_components(template, org=None, app=None):
    # This API applies the config regardless of whether the proxy is already configured.
    default_template_org_or_app = template["name"] == TEMPLATE_APP_NAME or template["name"] == TEMPLATE_ORG_NAME
    template = template["proprietary_components"]
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
                    # Is the entity matched with the default template?
                    if default_template_org_or_app:
                        # The template-org/app cannot specify proprietary component matches for every org/app.
                        # Therefore, if the org/app has PC and the template doesn't, inform that it should be removed.
                        if not template or not len(template):
                            pcsData.append(f'{entity_name} has proprietary component configuration that should be '
                                           f'removed. The default template does not specify proprietary component '
                                           f'configuration.')
                    # No. It's a named entity, so the PC config can be explicitly specified.
                    else:
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
                # Is the entity matched with the default template?
                if default_template_org_or_app:
                    # Therefore, if the template has PC and the org/app doesn't, inform that it should be added.
                    if pcsx is not None and not len(pcsx):
                        pcsData.append(f'{entity_name} is missing proprietary component configuration specified in the template.')
                # No. It's a named entity, so the PC config can be explicitly specified.
                else:
                    # No! Add it.
                    pcsData.append(f'Proprietary component {rendor_json(purge_empty_attributes(tpc), True)} should be '
                                   f'added to {entity_name}')

    if len(pcsData):
        proprietaryComps.append(len(pcsData))
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
        Advisories.update({'Custom Roles' : 'There are '+str(count)+' Custom roles.'})
        return f'{count} Custom roles.'
    return None


def validate_administrators():
    url = f'{iq_url}/rest/membershipMapping/global/global'
    data = get_url(url)
    policyAdminCount = 0
    systemAdminCount = 0
    for element in data['membersByRole']:
        role = element.pop('roleName')
        if role == 'Policy Administrator':
            policyAdminCount = len(element['membersByOwner'][0]['members'])
            Advisories.update({'Policy Administrators' : 'There are ' + str(policyAdminCount) + ' Custom roles.'})
        elif role == 'System Administrator':
            systemAdminCount = len(element['membersByOwner'][0]['members'])
            Advisories.update({'System Administrators' : 'There are ' + str(systemAdminCount) + ' Custom roles.'})
    return f'There are {policyAdminCount} Policy Administrators and {systemAdminCount} System Administrators.'


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
        contMonitoring.append(f'Continuous monitoring should be inherited for {entity_name}.')
        return f'Continuous monitoring should be inherited for {entity_name}.'
    contMonitoring.append(f'Continuous monitoring stage should be the {rendor_json(template)} for {entity_name}.')
    return f'Continuous monitoring stage should be the {rendor_json(template)} stage for {entity_name}.'


def validate_data_purging(template, org):
    url = f'{iq_url}/api/v2/dataRetentionPolicies/organizations/{org["id"]}'
    data = get_url(url)

    if data == template:
        return None
    if template == None:
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
            dataPurging.append(len(dpData))
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
                acData.append(f"Application Category '{ac['name']}' should be removed from '{org_name}'.")

    if template is not None:
        # Iterate over the ACs in the template
        for ac in template:
            try:
                # Does the template AC exist in the data for the org?
                data.index(ac)
            except (ValueError, AttributeError):
                # No! Add it.
                acData.append(f"Application Category '{ac['name']}' should be added to '{org_name}'.")
    if len(acData):
        appCategories.append(len(acData))
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
        compLabels.append(len(cl_data))
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
        ltgAdvisories.append(len(ltg_data))
        return ltg_data
    return None


def validate_ldap_instances():
    url = f'{iq_url}/rest/config/ldap'
    lc = item_count(get_url(url))
    Advisories.update({'LDAP Connections' : 'There are '+str(lc)+' LDAP servers configured.'})
    return f'{lc} LDAP server(s).'


def validate_email_server_connection():
    url = f'{iq_url}/api/v2/config/mail'
    es = item_count(get_url(url), True)
    Advisories.update({'Email Server' : 'There are '+str(es)+' Email servers configured.'})
    return f'{es} Email server.'


def validate_users():
    url = f'{iq_url}/rest/user'
    uc = item_count(get_url(url))
    Advisories.update({'Users' : 'There are '+str(uc)+' local users.'})
    return f'{uc} local users.'


def set_roles():
    global roles
    url = f'{iq_url}/api/v2/applications/roles'
    data = get_url(url)
    for role in data['roles']:
        roles[role['id']] = role['name']


def set_webhooks():
    global webhooks
    url = f'{iq_url}/rest/config/webhook'
    data = get_url(url)
    if data is not None:
        for webhook in data:
            webhooks[webhook['id']] = webhook['description']


# Write the data to a file...
def validate_data(data, filename):
    with open(filename, 'w') as outfile:
        json.dump(data, outfile, indent=2)
    persistedMessages.append(f'Persisted data to {filename}')
    #print(f'Persisted data to {filename}')                 ###


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
