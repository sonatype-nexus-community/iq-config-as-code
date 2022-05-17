#!/usr/bin/env python
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
import enum
from datetime import datetime
from typing import Dict, Optional, Type, TypeVar

from .command import _version, BaseCommand
from .command.apply import Apply
from .command.healthcheck import Healthcheck
from .command.scrape import Scrape

BC = TypeVar('BC', bound=BaseCommand)


@enum.unique
class _CLI_MODE(enum.Enum):
    APPLY = 'apply'
    HEALTHCHECK = 'healthcheck'
    SCRAPE = 'scrape'


_SUBCOMMANDS: Dict[_CLI_MODE, Type[BC]] = {
    _CLI_MODE.APPLY: Apply,
    _CLI_MODE.HEALTHCHECK: Healthcheck,
    _CLI_MODE.SCRAPE: Scrape
}


class IqConfigAsCodeCmd:
    _DEBUG_ENABLED: bool = False

    def __init__(self, args: argparse.Namespace) -> None:
        self._arguments: argparse.Namespace = args

        if self._arguments.debug_enabled:
            IqConfigAsCodeCmd._DEBUG_ENABLED = True
            IqConfigAsCodeCmd._debug_message('!!! DEBUG MODE ENABLED !!!')
            IqConfigAsCodeCmd._debug_message('Parsed Arguments: {}'.format(self._arguments))

    def execute(self) -> None:
        # Determine primary command and then hand off to that Command handler
        print(f'Executing with args: {self._arguments}')
        print(f'Keys: {_SUBCOMMANDS.keys()}')
        if self._arguments.cmd:
            command = _SUBCOMMANDS[_CLI_MODE(self._arguments.cmd)]
            exit_code: int = command(arguments=self._arguments, debug_func=IqConfigAsCodeCmd._debug_message).execute()
            exit(exit_code)
        else:
            IqConfigAsCodeCmd.get_arg_parser().print_help()

    @staticmethod
    def get_arg_parser(*, prog: Optional[str] = None) -> argparse.ArgumentParser:
        arg_parser = argparse.ArgumentParser(prog=prog, description='Nexus IQ Config as Code')

        # Add global options
        arg_parser.add_argument('-v', '--version', help='show which version of jake you are running',
                                action='version',
                                version=f'nexus-iq-casc {_version}')
        arg_parser.add_argument('-w', '--warn-only', action='store_true', dest='warn_only',
                                help='prevents exit with non-zero code when issues have been detected')
        arg_parser.add_argument('-X', action='store_true', help='enable debug output', dest='debug_enabled')

        arg_parser.add_argument('--no-verify-ssl', help='Disable SSL validation when connecting to Nexus IQ Server',
                                action='store_true', dest='disable_ssl_verification')

        subparsers = arg_parser.add_subparsers(title='nexus-iq-casc sub-commands', dest='cmd', metavar='')
        for cli_mode, cmd in _SUBCOMMANDS.items():
            cmd.setup_argument_parser(
                arg_parser=subparsers.add_parser(
                    name=cli_mode.value,
                    help=cmd.get_argument_parser_help()
                )
            )

        return arg_parser

    @staticmethod
    def _debug_message(message: str) -> None:
        if IqConfigAsCodeCmd._DEBUG_ENABLED:
            print(f'[DEBUG] - {datetime.now()} - {message}')

    @staticmethod
    def _error_and_exit(message: str, exit_code: int = 1) -> None:
        print('[ERROR] - {} - {}'.format(datetime.now(), message))
        exit(exit_code)


def main(*, prog_name: Optional[str] = None) -> None:
    parser = IqConfigAsCodeCmd.get_arg_parser(prog=prog_name)
    args = parser.parse_args()
    IqConfigAsCodeCmd(args).execute()


if __name__ == "__main__":
    main()
