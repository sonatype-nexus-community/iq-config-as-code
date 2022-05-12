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
import sys
import urllib3
from abc import ABC, abstractmethod
from nexus_iq import ApiClient
from nexus_iq.configuration import Configuration
from typing import Optional

if sys.version_info >= (3, 8):
    from importlib.metadata import version as meta_version, PackageNotFoundError as PnfE
    from typing import final, Protocol
else:
    from importlib_metadata import version as meta_version, PackageNotFoundError as PnfE
    from typing_extensions import final, Protocol

try:
    _version: Optional[str] = str(meta_version(__package__))  # type: ignore[no-untyped-call]
except PnfE:
    _version = 'DEVELOPMENT'


class DebugMessageCallable(Protocol):
    def __call__(self, message: str) -> None:
        pass


class BaseCommand(ABC):

    def __init__(self, *, arguments: argparse.Namespace) -> None:
        # Parsed Arguments
        self._arguments = arguments
        self._api_client: Optional[ApiClient] = None

    @property
    def arguments(self) -> argparse.Namespace:
        return self._arguments

    @final
    def api_client(self) -> ApiClient:
        return ApiClient(configuration=self.api_client_config())

    def api_client_config(self) -> Configuration:
        auth = self.arguments.iq_auth.split(':')
        config = Configuration(host=self.arguments.iq_server_url, username=auth[0], password=auth[1])
        if self.arguments.disable_ssl_verification:
            urllib3.disable_warnings()
            config.verify_ssl = False
        return config

    @abstractmethod
    def handle_args(self) -> int:
        pass

    def execute(self) -> int:
        return self.handle_args()

    @staticmethod
    @abstractmethod
    def get_argument_parser_help() -> str:
        pass

    @staticmethod
    @abstractmethod
    def setup_argument_parser(arg_parser: argparse.ArgumentParser) -> None:
        pass
