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

from . import BaseCommand


class Scrape(BaseCommand):

    def __init__(self, *, arguments: argparse.Namespace) -> None:
        super().__init__(arguments=arguments)

    def handle_args(self) -> int:
        pass

    @staticmethod
    def get_argument_parser_help() -> str:
        return 'Scrape configuration from your Nexus IQ Server'

    @staticmethod
    def setup_argument_parser(arg_parser: argparse.ArgumentParser) -> None:
        arg_parser.add_argument('-u', '--server-url', help='Full http(s):// URL to your Nexus Lifecycle server',
                                metavar='https://localhost:8070', required=True, dest='iq_server_url')

        arg_parser.add_argument('-a', '--auth', help='Basic Auth used to authenticate with IQ',
                                metavar='USERNAME:PASSWORD', required=False, dest='iq_auth')

        arg_parser.add_argument('-o', '--output-dir', help='Directory to write output to',
                                metavar='/tmp', default='/tmp', required=False, dest='output_directory')

        arg_parser.add_argument('-y', '--orgs-and-apps',
                                help='Specific organisation(s) and specific application(s) public-id(s)',
                                metavar='My Org,app-id-1', required=False, dest='iq_orgs_apps')
