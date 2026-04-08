import sys
import re
import io

from typing import Iterator, Optional, List
from abc import ABC, abstractmethod
from re import Pattern


class RuleSet(ABC):
    @abstractmethod
    def identify_resource(self, line: str) -> Optional[str]:
        pass

    @abstractmethod
    def match(self, line: str) -> Optional[str]:
        pass

    @abstractmethod
    def warnings_or_errors(self, line: str) -> Optional[str]:
        pass


class StraceCredentialsExfiltrationRuleSet(RuleSet):

    @staticmethod
    def compile_package_rule(venv_directory: str) -> Pattern:
        return re.compile(
            r"^\[pid [0-9]+\] mkdir\(\"%s/lib/python.*/site-packages/([a-zA-Z][a-zA-Z0-9_-]+)\", 0777\) = 0"
            % re.escape(venv_directory)
        )

    @staticmethod
    def path_access(path: str) -> Pattern:
        return re.compile(
            r"^\[pid [0-9]+\] (statx|openat|access)\(AT_FDCWD, \"(%s).*$" % path
        )

    @classmethod
    def compile_rules(cls, home_directory: str) -> List[Pattern]:
        home_directories = ["/root", home_directory]
        relative_pathes = [
            "/.ssh",
            "/.ssh/id_rsa",
            "/.ssh/id_ed25519",
            "/.ssh/id_ecdsa",
            "/.ssh/id_dsa",
            "/.ssh/authorized_keys",
            "/.ssh/known_hosts",
            "/.ssh/config",
            "/.git-credentials",
            "/.gitconfig",
            "/.aws",
            "/.aws/credentials",
            "/.aws/config",
        ]

        rules = []
        for directory in home_directories:
            for relative_path in relative_pathes:
                rules.append(cls.path_access(directory + relative_path))

        return rules

    def __init__(self, home_directory: str, venv_directory: str) -> None:
        self.package_rule = self.compile_package_rule(venv_directory)
        self.rules = self.compile_rules(home_directory)

    def identify_resource(self, line: str) -> Optional[str]:
        if line.startswith("Package: "):
            return line[9:]

        if match := self.package_rule.match(line):
            return match.groups()[0]

    def match(self, line: str) -> Optional[str]:
        for rule in self.rules:
            if match := rule.match(line):
                return match.groups()[1]

    def warnings_or_errors(self, line: str) -> Optional[str]:
        if line.startswith("WARNING: ") or line.startswith("ERROR: "):
            return line


class ScannerObserver(ABC):
    @abstractmethod
    def resource_identified(self, resource: str):
        pass

    @abstractmethod
    def match_detected(self, resource: str, pattern: str):
        pass


class StraceScanner:
    def __init__(
        self, rule_set: RuleSet, observer: ScannerObserver, trace_file: Optional[str]
    ) -> None:
        self.rule_set = rule_set
        self.observer = observer
        self.trace_file = trace_file
        self.resource = ""

    def _scan_lines(self, lines: Iterator, fp: Optional[io.TextIOBase] = None):
        for line in lines:
            if fp:
                fp.write(line)

            if msg := self.rule_set.warnings_or_errors(line):
                print(msg, file=sys.stderr)

            if resource := self.rule_set.identify_resource(line):
                self.resource = resource
                continue

            if match := self.rule_set.match(line):
                self.observer.match_detected(self.resource, match)

    def scan(self, lines: Iterator):
        if self.trace_file:
            with open(self.trace_file, "w") as fp:
                self._scan_lines(lines, fp)
        else:
            self._scan_lines(lines)
