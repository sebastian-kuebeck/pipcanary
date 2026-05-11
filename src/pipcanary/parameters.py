import tomli as toml
import os
import logging

from datetime import datetime
from typing import Dict, Any, List, Optional
from abc import ABC, abstractmethod
import argparse
from argparse import ArgumentParser, Namespace
from urllib.parse import urlsplit

from .errors import InvalidArgumentError, RequirementsError
from .logging import LOG_LEVELS
from .requirements import Requirements
from .package_auditor import PipOptions, AuditSelection

logger = logging.getLogger(__name__)


class classproperty:
    def __init__(self, fget):
        self.fget = fget  # Store the getter function

    def __get__(self, instance, owner):
        return self.fget(owner)

    def setter(self, fset):
        self.fset = fset
        return self

    def __set__(self, instance, value):
        raise AttributeError("can't set attribute")


class Parameter(ABC):
    @classproperty
    def name(cls) -> str:
        raise NotImplementedError()

    @classproperty
    def arg_name(cls) -> str:
        name = cls.name
        assert "-" not in name
        return "--%s" % cls.name.replace("_", "-")

    @abstractmethod
    def add_argument(self, parser: ArgumentParser):
        pass

    @property
    def default_value(self) -> Any:
        return None

    @property
    def is_config_parameter(self) -> bool:
        return True

    @property
    def is_list(self) -> bool:
        return False

    def validate(self, arg: str, value: Any) -> Any:
        return value

    def arg_value(self, value: Any) -> Any:
        return self.validate(self.arg_name, value)

    def config_value(self, value: Any) -> Any:
        return self.validate(self.name, value)


class IntParameter(Parameter):
    def validate(self, arg: str, value: Any) -> Any:
        if isinstance(value, int):
            return value
        elif isinstance(value, str):
            try:
                return int(value)
            except ValueError:
                raise InvalidArgumentError(arg, f"Expected integer but got '{value}'")
        raise InvalidArgumentError(arg, "Expected single integer value")


class StringParameter(Parameter):
    def validate(self, arg: str, value: Any) -> Any:
        if not isinstance(value, str):
            raise InvalidArgumentError(arg, "Expected single value")
        return value


class UrlParameter(StringParameter):
    def validate(self, arg: str, value: Any) -> Any:
        url = super().validate(arg, value)
        try:
            urlsplit(url)
            return url
        except ValueError:
            raise InvalidArgumentError(arg, "Malformed URL: '{value}'")


class BooleanParameter(Parameter):
    def validate(self, arg: str, value: Any) -> Any:
        if isinstance(value, bool):
            return value
        else:
            raise InvalidArgumentError(arg, "Expected boolean value")


class StringListParameter(Parameter):
    def validate(self, arg: str, value: Any) -> Any:
        if not isinstance(value, list):
            raise InvalidArgumentError(arg, "Expected list of strings")

        for i, v in enumerate(value):
            if not isinstance(v, str):
                raise InvalidArgumentError(
                    arg, f"Expected a string for list element {i + 1} but got '{v}'"
                )

        return value

    @property
    def is_list(self) -> bool:
        return True

    @property
    def default_value(self) -> Any:
        return []


class ExistingFileParameter(StringParameter):

    def validate(self, arg: str, value: Any) -> Any:
        path = super().validate(arg, value)
        if not os.path.isfile(path):
            raise InvalidArgumentError(
                arg, f"Path '{path}' does not exist or is not a file."
            )
        return path


class FileParameter(StringParameter):

    def validate(self, arg: str, value: Any) -> Any:
        path = super().validate(arg, value)
        dir = os.path.abspath(os.path.dirname(path))

        if not os.path.isdir(dir):
            raise InvalidArgumentError(
                arg, f"Directory '{dir}' does not exist or is not a directory."
            )
        return path


class DirectoryParameter(StringParameter):

    def validate(self, arg: str, value: Any) -> Any:
        path = super().validate(arg, value)
        if not os.path.isdir(path):
            raise InvalidArgumentError(
                arg, f"Path '{path}' does not exist or is not a directory."
            )
        return path


class DateTimeParameter(Parameter):
    def validate(self, arg: str, value: Any) -> Any:
        if not isinstance(value, str):
            raise InvalidArgumentError(arg, "Expected single ISO 8601 formatted date")

        try:
            return datetime.fromisoformat(value)
        except ValueError:
            raise InvalidArgumentError(
                arg,
                f"Malformed date value: '{value}'. Expected ISO 8601 formatted date",
            )


class ProjectFile(ExistingFileParameter):
    local_file = "./pyproject.toml"

    @classproperty
    def name(cls) -> str:
        return "project"

    @property
    def is_config_parameter(self) -> bool:
        return False

    def add_argument(self, parser: ArgumentParser):
        parser.add_argument(
            "-p",
            self.arg_name,
            help=(
                "The project file in TOML format. Usually pyproject.toml. "
                "If neither -p or -r are set, ./pyproject.toml or if not exists ./requirements.txt is scanned."
            ),
        )


class RequirementsFile(ExistingFileParameter):
    local_file = "./requirements.txt"

    @classproperty
    def name(cls) -> str:
        return "requirement"

    @property
    def is_config_parameter(self) -> bool:
        return False

    def add_argument(self, parser: ArgumentParser):
        parser.add_argument(
            "-r",
            self.arg_name,
            help=("The requirements file, usually requirements.txt."),
        )


class LockedRequirementsFile(FileParameter):

    @classproperty
    def name(cls) -> str:
        return "locked_requirement"

    def add_argument(self, parser: ArgumentParser):
        parser.add_argument(
            "-l",
            self.arg_name,
            help=(
                'generates a "locked" file with all requirements, the scanned version with hashes'
            ),
        )


class MaxUploadTime(DateTimeParameter):
    @classproperty
    def name(cls) -> str:
        return "max_upload_time"

    def add_argument(self, parser: ArgumentParser):
        parser.add_argument(
            self.arg_name,
            help=(
                "Maximum upload time for all packages (ISO 8601 date and time format). "
                "Example: --max-upload-time='2026-04-07T07:43:51+0000'"
            ),
        )


class CoolDownPhase(IntParameter):
    @classproperty
    def name(cls) -> str:
        return "cool_down_phase_days"

    def add_argument(self, parser: ArgumentParser):
        parser.add_argument(
            "-c",
            self.arg_name,
            help=(
                "Cool-down phase for packages in days for new package uploads. Default: 7"
            ),
        )

    @property
    def default_value(self) -> Any:
        return 7


class AdditionalDirectory(DirectoryParameter):
    @classproperty
    def name(cls) -> str:
        return "additional_directory"

    def add_argument(self, parser: ArgumentParser):
        parser.add_argument(
            "-d",
            self.arg_name,
            help=(
                "Additional directory mapped into the sandbox while scanning"
                "Make sure this directory does not contain sensitive information!"
            ),
        )


class TraceFile(StringParameter):
    @classproperty
    def name(cls) -> str:
        return "trace_file"

    def add_argument(self, parser: ArgumentParser):
        parser.add_argument(
            "-t",
            self.arg_name,
            help=("The trace file for further analysis"),
        )


class Sandbox(BooleanParameter):
    @classproperty
    def name(cls) -> str:
        return "sandbox"

    @property
    def is_config_parameter(self) -> bool:
        return False

    def add_argument(self, parser: ArgumentParser):
        parser.add_argument(
            self.arg_name,
            help=(
                "Run with sandbox (default). No sandbox might be safe if you are already running within a sandbox!"
            ),
            action=argparse.BooleanOptionalAction,
        )

    @property
    def default_value(self) -> Any:
        return True


class IndexUrl(UrlParameter):
    @classproperty
    def name(cls) -> str:
        return "index_url"

    def add_argument(self, parser: ArgumentParser):
        parser.add_argument(
            "-i",
            self.arg_name,
            help=("URL to PyPi compatible repository"),
        )


class ExtraIndexUrl(UrlParameter):
    @classproperty
    def name(cls) -> str:
        return "extra_index_url"

    def add_argument(self, parser: ArgumentParser):
        parser.add_argument(
            "--extra-index-url",
            help=("Extra URL to PyPi compatible repository"),
        )


class TemporaryDirectory(DirectoryParameter):
    @classproperty
    def name(cls) -> str:
        return "temporary_directory"

    def add_argument(self, parser: ArgumentParser):
        parser.add_argument(
            self.arg_name,
            help=("Temporary directory. Default: /tmp"),
        )


class AdditionalPipArgs(StringParameter):
    @classproperty
    def name(cls) -> str:
        return "pip_args"

    def add_argument(self, parser: ArgumentParser):
        parser.add_argument(
            self.arg_name,
            help=("additional arguments for pip install during the scan process"),
        )


class LogLevel(StringParameter):
    @classproperty
    def name(cls) -> str:
        return "log_level"

    def add_argument(self, parser: ArgumentParser):
        parser.add_argument(
            self.arg_name,
            help=("The log level. Supported levels are: %s" % (", ".join(LOG_LEVELS))),
        )

    def validate(self, arg: str, value: Any) -> Any:
        level = super().validate(arg, value)
        if level not in LOG_LEVELS:
            raise InvalidArgumentError(
                arg,
                "Invalid log level '%s'. Supported levels are: %s"
                % (level, ", ".join(LOG_LEVELS)),
            )
        return level

    @property
    def default_value(self) -> Any:
        return "INFO"


class DoNotScan(StringListParameter):
    @classproperty
    def name(cls) -> str:
        return "do_not_scan"

    def add_argument(self, parser: ArgumentParser):
        parser.add_argument(
            self.arg_name,
            action="append",
            help=("Add packages that should not be scanned"),
        )


class IgnoreVuln(StringListParameter):
    @classproperty
    def name(cls) -> str:
        return "ignore_vuln"

    def add_argument(self, parser: ArgumentParser):
        parser.add_argument(
            self.arg_name,
            action="append",
            help=("Ignore the given vulnerability"),
        )


class AllowUploadTime(StringListParameter):
    @classproperty
    def name(cls) -> str:
        return "allow_upload_time"

    def validate(self, arg: str, value: Any) -> Any:
        values = super().validate(arg, value)

        max_upload_time_for: Dict[str, datetime] = {}
        for i, rule in enumerate(values):
            try:
                package, max_upload_time = rule.split("<=")
                max_upload_time_for[package] = datetime.fromisoformat(max_upload_time)
            except ValueError:
                raise InvalidArgumentError(
                    arg,
                    f"Malformed argument {i + 1}: Expected <package_name><=<max upload time> but got '{rule}'",
                )
        return max_upload_time_for

    def add_argument(self, parser: ArgumentParser):
        parser.add_argument(
            "-a",
            self.arg_name,
            action="append",
            help=(
                "Maximum upload time for a single package (ISO 8601 date and time format). "
                "Example: --allow-upload-time='requests<=2026-04-07T07:43:51+0000"
            ),
        )


PARAMETERS: List[Parameter] = [
    ProjectFile(),
    RequirementsFile(),
    LockedRequirementsFile(),
    MaxUploadTime(),
    CoolDownPhase(),
    AdditionalDirectory(),
    TraceFile(),
    Sandbox(),
    IndexUrl(),
    ExtraIndexUrl(),
    TemporaryDirectory(),
    AdditionalPipArgs(),
    LogLevel(),
    DoNotScan(),
    IgnoreVuln(),
    AllowUploadTime(),
]


class PipCanaryParameters:
    def __init__(self, params: Optional[List[Parameter]] = None) -> None:
        params = params or PARAMETERS
        self.params: Dict[str, Parameter] = {}
        for param in params:
            assert param.name not in self.params, f"Duplicate parameter {param.name}"
            self.params[param.name] = param

        self.values = {}

    def add_arguments(self, parser: ArgumentParser):
        for param in self.params.values():
            param.add_argument(parser)

    def _config_parameters_from_file(self, path: str) -> Dict[str, Any]:
        try:
            with open(path, "rb") as input:
                config = toml.load(input)
                tool = config.get("tool", {})
                return tool.get("pipcanary", {})
        except (KeyError, ValueError, AssertionError) as e:
            raise RequirementsError(f"Malformed project TOML file: {path}: {str(e)}")
        except IOError as e:
            raise RequirementsError(f"Failed to load project file: {path}: {str(e)}")

    def _add_args(self, args: Namespace):
        for name, param in self.params.items():
            if name in args:
                value = getattr(args, name)
                if value is not None:
                    self.values[name] = param.arg_value(value)

    def _add_config_parameters(self, config_params: Dict[str, Any]):
        for name, param in self.params.items():
            if param.is_config_parameter and name in config_params:
                value = config_params[name]
                if value is not None:
                    config_value = param.config_value(value)
                    if name in self.values and param.is_list:
                        self.values[name].extend(config_value)
                    elif name not in self.values:
                        self.values[name] = param.config_value(value)

    def _add_defaults(self):
        for name, param in self.params.items():
            if name not in self.values:
                self.values[name] = param.default_value

    def fill(self, args: Namespace):
        self._add_args(args)

        project_file = self.values.get(ProjectFile.name)
        requirements_file = self.values.get(RequirementsFile.name)

        if not project_file and not requirements_file:
            if os.path.isfile(ProjectFile.local_file):
                project_file = ProjectFile.local_file

        if project_file:
            config_params = self._config_parameters_from_file(project_file)
            self.values[ProjectFile.name] = project_file
            self._add_config_parameters(config_params)

        self._add_defaults()

    def requirements(self) -> Requirements:
        requirements = Requirements()
        project_file = self.values.get(ProjectFile.name)
        requirements_file = self.values.get(RequirementsFile.name)

        if requirements_file:
            requirements = requirements.join(
                Requirements.from_requirements_file(requirements_file)
            )

        if project_file:
            requirements = requirements.join(
                Requirements.from_project_file(
                    project_file, requirements_file is not None
                )
            )

        if not project_file and not requirements_file:
            requirements_file = RequirementsFile.local_file
            if requirements_file:
                requirements = requirements.join(
                    Requirements.from_requirements_file(requirements_file)
                )

        if len(requirements) == 0:
            raise InvalidArgumentError(ProjectFile.name, "No requirements found")

        return requirements

    def pipOptions(self) -> PipOptions:
        return PipOptions(
            temporary_directory=self.values[TemporaryDirectory.name],
            additional_directory=self.values[AdditionalDirectory.name],
            index_url=self.values[IndexUrl.name],
            extra_index_url=self.values[ExtraIndexUrl.name],
            additional_args=self.values[AdditionalPipArgs.name],
        )

    def auditSelection(self, current_time: Optional[datetime] = None):
        return AuditSelection(
            max_upload_time=self.values[MaxUploadTime.name],
            cool_down_phase_days=self.values[CoolDownPhase.name],
            allowed_upload_times=self.values[AllowUploadTime.name],
            ignore_vulns=self.values[IgnoreVuln.name],
            current_time=current_time,
        )

    def __getitem__(self, index):
        return self.values[index]

    def __contains__(self, index):
        return index in self.values

    @property
    def sandbox(self) -> bool:
        return self.values[Sandbox.name]

    @property
    def log_level(self) -> str:
        return self.values[LogLevel.name]

    @property
    def locked_requirements_file(self) -> Optional[str]:
        return self.values[LockedRequirementsFile.name]

    @property
    def do_not_scan(self) -> List[str]:
        return self.values[DoNotScan.name]

    @property
    def trace_file(self) -> Optional[str]:
        return self.values[TraceFile.name]
