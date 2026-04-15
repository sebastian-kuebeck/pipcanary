import os
import re
import tomli
import tempfile

from typing import List, Optional

from .errors import RequirementsError


class Requirements:
    PYPI_REQUIREMENT = re.compile(r"^([a-zA-Z][a-zA-Z0-9-_]*)([=><!\^\~]|\w).*")

    def __init__(self, requirements: List[str]) -> None:
        self.requirements = requirements

    @classmethod
    def from_requirements_file(cls, path: str):
        requirements = []
        try:
            with open(path, "r") as input:
                for line in input.readlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        requirements.append(line)
            return cls(requirements)
        except IOError as e:
            raise RequirementsError(f"Failed to load project file: {path}: {str(e)}")

    @classmethod
    def from_project_file(cls, path: str):
        try:
            with open(path, "rb") as input:
                dependencies = tomli.load(input)["project"]["dependencies"]
                assert isinstance(dependencies, list)
                return cls(dependencies)
        except (KeyError, ValueError, AssertionError) as e:
            raise RequirementsError(f"Malformed project TOML file: {path}: {str(e)}")
        except IOError as e:
            raise RequirementsError(f"Failed to load project file: {path}: {str(e)}")

    def skip_packages(self, packages: List[str]):
        reduced_rquirements: List[str] = []
        for requirement in self.requirements:
            match = self.PYPI_REQUIREMENT.match(requirement)
            if match:
                package = match.groups()[0]
                if package in packages:
                    pass
                elif requirement in packages:
                    pass
                else:
                    reduced_rquirements.append(requirement)
        self.requirements = reduced_rquirements

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
