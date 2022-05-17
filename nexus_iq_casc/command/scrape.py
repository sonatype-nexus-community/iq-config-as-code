# encoding: utf-8

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
import importlib
import re
from nexus_iq import ApiException
from nexus_iq.exceptions import NotFoundException
from nexus_iq_internal import ApiException as RestApiException
from nexus_iq_internal.exceptions import NotFoundException as RestNotFoundException
from typing import Any, Dict

from . import BaseCommand, DebugMessageCallable

_OUTPUT_MAPPING = {
    'System-Config.json': {
        "api": {
            "email_server": {"api": "ConfigurationApi", "method": "get_mail_configuration"},
            "proxy": {"api": "ConfigurationApi", "method": "get_http_proxy_configuration"}
        },
        "rest": {
            "administrators": {"api": "SecurityApi", "method": "membership_mapping_owner_type_owner_id_get", "params": {
                "owner_type": "global", "owner_id": "global"
            }},
            "custom_roles": {"api": "SecurityApi", "method": "security_roles_get"},
            "ldap_connections": {"api": "ConfigurationApi", "method": "get_ldap_servers"},
            "system_notice": {"api": "ConfigurationApi", "method": "get_system_notice"},
            "users": {"api": "UserApi", "method": "get_users"},
            "webhooks": {"api": "ConfigurationApi", "method": "get_all_webhooks"}
        }
    }
}

# # Parses and applies all the 'administrative' configuration for Nexus IQ
# systemConf['success_metrics'] = persist_success_metrics()
# systemConf['automatic_applications'] = persist_auto_applications()
# systemConf['automatic_source_control'] = persist_automatic_source_control()
# systemConf['success_metrics_reports'] = persist_success_metrics_reports()
# persist_data(systemConf, f'{output_dir}System-Config.json')

_API_TO_MODULE_PATTERN = re.compile(r'(?<!^)(?=[A-Z])')


def _api_to_module_name(api_name: str) -> str:
    return _API_TO_MODULE_PATTERN.sub('_', api_name).lower()


class Scrape(BaseCommand):

    def __init__(self, *, arguments: argparse.Namespace, debug_func: DebugMessageCallable) -> None:
        super().__init__(arguments=arguments)
        self._debug_message = debug_func

    def handle_args(self) -> int:
        config = self._scrape_system_configuration()

        print(config)

        return 0

    def _scrape_system_configuration(self) -> Dict[str, Any]:
        filename_key = 'System-Config.json'
        config: Dict[str, Any] = {}

        with self.api_client() as api_client:
            for k, v in _OUTPUT_MAPPING[filename_key]['api'].items():
                api_class = v['api']
                api_method = v['method']
                try:
                    api = getattr(
                        importlib.import_module(f'nexus_iq.api.{_api_to_module_name(api_name=api_class)}'), api_class)(
                        api_client=api_client
                    )
                    method = getattr(api, api_method)
                    params = v['params'] if 'params' in v.items() else {}
                    config[k] = method(**params)
                except NotFoundException:
                    pass
                except ApiException as e:
                    self._debug_message(message=f'Exception calling ConfigurationApi->get_mail_configuration(): {e}')

        with self.rest_api_client() as rest_api_client:
            for k, v in _OUTPUT_MAPPING[filename_key]['rest'].items():
                api_class = v['api']
                api_method = v['method']
                try:
                    api = getattr(
                        importlib.import_module(
                            f'nexus_iq_internal.api.{_api_to_module_name(api_name=api_class)}'), api_class
                    )(
                        api_client=rest_api_client
                    )
                    method = getattr(api, api_method)
                    params = v['params'] if 'params' in v.keys() else {}
                    config[k] = method(**params)
                except RestNotFoundException:
                    pass
                except RestApiException as e:
                    self._debug_message(message=f'Exception calling ConfigurationApi->get_mail_configuration(): {e}')

        return config

    @staticmethod
    def get_argument_parser_help() -> str:
        return 'Scrape configuration from your Nexus IQ Server'

    @staticmethod
    def setup_argument_parser(arg_parser: argparse.ArgumentParser) -> None:
        arg_parser.add_argument('-u', '--server-url', help='Full http(s):// URL to your Nexus Lifecycle server',
                                metavar='https://localhost:8070', required=False, dest='iq_server_url')

        arg_parser.add_argument('-a', '--auth', help='Basic Auth used to authenticate with IQ',
                                metavar='USERNAME:PASSWORD', default='admin:admin123', required=False, dest='iq_auth')

        arg_parser.add_argument('-o', '--output-dir', help='Directory to write output to',
                                metavar='/tmp', default='/tmp', required=False, dest='output_directory')

        arg_parser.add_argument('-y', '--orgs-and-apps',
                                help='Specific organisation(s) and specific application(s) public-id(s)',
                                metavar='My Org,app-id-1', required=False, dest='iq_orgs_apps')
