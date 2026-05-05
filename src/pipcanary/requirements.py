import os
import re
import tomli as toml
import tempfile

from typing import List, Optional

from .errors import RequirementsError


class Requirements:
    PYPI_REQUIREMENT = re.compile(r"^([a-zA-Z][a-zA-Z0-9-_]*)([=><!\^\~\[\(@]|\s).*")

    def __init__(self, requirements: List[str]) -> None:
        self.requirements = requirements

    @classmethod
    def from_requirements_file(cls, path: str):
        try:
            with open(path, "r") as input:
                return cls(cls.parse_requirements(input.readlines()))
        except IOError as e:
            raise RequirementsError(f"Failed to load project file: {path}: {str(e)}")

    @classmethod
    def parse_requirements(cls, lines: List[str]) -> List[str]:
        requirements = []
        multiline_requirement: str = ""
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if line.endswith("\\"):
                multiline_requirement += line[:-1]
                continue

            if multiline_requirement:
                requirement = multiline_requirement + line
                multiline_requirement = ""
            else:
                requirement = line

            requirements.append(requirement)
        if multiline_requirement:
            requirements.append(multiline_requirement)
        return requirements

    @classmethod
    def from_project_file(cls, path: str):
        try:
            with open(path, "rb") as input:
                dependencies = toml.load(input)["project"]["dependencies"]
                assert isinstance(dependencies, list)
                return cls(dependencies)
        except (KeyError, ValueError, AssertionError) as e:
            raise RequirementsError(f"Malformed project TOML file: {path}: {str(e)}")
        except IOError as e:
            raise RequirementsError(f"Failed to load project file: {path}: {str(e)}")

    def skip_packages(self, requirements_or_packages: List[str]) -> "Requirements":
        reduced_requirements: List[str] = []
        for requirement in self.requirements:
            match = self.PYPI_REQUIREMENT.match(requirement)
            if match:
                package = match.groups()[0]
                if package not in requirements_or_packages:
                    reduced_requirements.append(requirement)
            else:
                if requirement not in requirements_or_packages:
                    reduced_requirements.append(requirement)

        return Requirements(reduced_requirements)

    def write_to_temporary_file(self) -> str:
        fp: Optional[int] = None
        try:
            fp, requirements_path = tempfile.mkstemp(suffix="-pipcanary")
            for requirement in self.requirements:
                os.write(fp, f"{requirement}\n".encode())
            return requirements_path
        except IOError as e:
            raise RequirementsError(f"Failed to write temporary file: {str(e)}")
        finally:
            if fp:
                os.close(fp)
