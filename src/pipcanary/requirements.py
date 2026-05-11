import os
import re
import tomli as toml
import tempfile

from typing import List, Optional, Dict, Any, Union

from .errors import RequirementsError


class Requirements:
    PYPI_REQUIREMENT = re.compile(r"^([a-zA-Z][a-zA-Z0-9-_]*)([=><!\^\~\[\(@]|\s).*")

    def __init__(self, requirements: Optional[List[str]] = None) -> None:
        self._requirements = requirements or []

    @classmethod
    def from_requirements_file(cls, path: str):
        try:
            with open(path, "r") as input:
                requirements = cls(cls.parse_requirements(input.readlines()))
                if not requirements:
                    raise RequirementsError(f"No requirements found in {path}")
                return requirements
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
    def extract_dependency_groups(
        cls, groups: List[str], all_sections: Dict[str, Any]
    ) -> List[str]:
        dependencies: List[str] = []

        def flatten(la: List[Any]) -> List[str]:
            ls = []
            for e in la:
                if isinstance(e, str):
                    ls.append(e)
                elif isinstance(e, list):
                    ls.extend(flatten(e))
            return ls

        for group in groups:
            path: List[str] = group.split(".")
            section: Dict[str, Any] = all_sections
            child: Optional[Union[List[str], Dict[str, Any]]] = None
            for key in path:
                child = section.get(key)
                if child is None:
                    break
                elif isinstance(child, dict):
                    section = child
                elif isinstance(child, list):
                    pass
                else:
                    child = None
                    break

            if not child:
                continue
            elif isinstance(child, list):
                dependencies.extend(flatten(child))
            else:
                dependencies.extend(flatten(list(child.values())))

        return dependencies

    @classmethod
    def extract_dependencies(
        cls, path: str, all_sections: Dict[str, Any], allow_dynamic: bool = False
    ) -> List[str]:
        project_section = all_sections["project"]
        dynamic = project_section.get("dynamic", [])
        if "dependencies" in dynamic or "optional-dependencies" in dynamic:
            if allow_dynamic:
                return []
            else:
                raise RequirementsError(
                    "PipCanary does not support dynamic dependencies. Use pipcanary -r requirements.txt instead"
                )
        groups = [
            "project.dependencies",
            "project.optional-dependencies",
            "dependency-groups",
        ]
        dependencies = cls.extract_dependency_groups(groups, all_sections)
        if not dependencies:
            raise RequirementsError(f"No dependencies found in {path}")
        return dependencies

    @classmethod
    def from_project_file(cls, path: str, allow_dynamic: bool = False):
        try:
            with open(path, "rb") as input:
                all_sections = toml.load(input)

                return cls(cls.extract_dependencies(path, all_sections))
        except (KeyError, ValueError, AssertionError) as e:
            raise RequirementsError(f"Malformed project TOML file: {path}: {str(e)}")
        except IOError as e:
            raise RequirementsError(f"Failed to load project file: {path}: {str(e)}")

    def skip_packages(self, requirements_or_packages: List[str]) -> "Requirements":
        reduced_requirements: List[str] = []
        for requirement in self._requirements:
            match = self.PYPI_REQUIREMENT.match(requirement)
            if match:
                package = match.groups()[0]
                if package not in requirements_or_packages:
                    reduced_requirements.append(requirement)
            else:
                if requirement not in requirements_or_packages:
                    reduced_requirements.append(requirement)

        return Requirements(reduced_requirements)

    def join(self, other: "Requirements") -> "Requirements":
        return Requirements([*self._requirements, *other._requirements])

    def write_to_temporary_file(self) -> str:
        fp: Optional[int] = None
        try:
            fp, requirements_path = tempfile.mkstemp(suffix="-pipcanary")
            for requirement in self._requirements:
                os.write(fp, f"{requirement}\n".encode())
            return requirements_path
        except IOError as e:
            raise RequirementsError(f"Failed to write temporary file: {str(e)}")
        finally:
            if fp:
                os.close(fp)

    def __len__(self):
        return len(self._requirements)

    def list(self) -> List[str]:
        return self._requirements
