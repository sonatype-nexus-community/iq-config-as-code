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
from abc import ABC, abstractmethod
from typing import Optional

if sys.version_info >= (3, 8):
    from importlib.metadata import version as meta_version, PackageNotFoundError as PnfE
else:
    from importlib_metadata import version as meta_version, PackageNotFoundError as PnfE

try:
    _version: Optional[str] = str(meta_version(__package__))  # type: ignore[no-untyped-call]
except PnfE:
    _version = 'DEVELOPMENT'


class BaseCommand(ABC):

    def __init__(self, *, arguments: argparse.Namespace) -> None:
        # Parsed Arguments
        self._arguments: arguments

    @property
    def arguments(self) -> argparse.Namespace:
        return self._arguments

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
