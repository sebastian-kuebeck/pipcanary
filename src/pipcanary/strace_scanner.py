import os
import re

from typing import Iterator, Optional, Callable, List
from abc import ABC, abstractmethod
from re import Pattern

class RuleSet(ABC):
    @abstractmethod
    def identify_resource(self, line:str) -> Optional[str]:
        pass

    @abstractmethod
    def match(self, line:str) -> Optional[str]:
        pass

class StraceCredentialsExfiltrationRuleSet(RuleSet):

    @staticmethod
    def compile_paracke_rule(venv_directory: str) -> Pattern:
        # [pid 210676] mkdir("/tmp/tmp.tFxEKCJMPB-pipcanary/lib/python3.10/site-packages/tox", 0777) = 0
        return  re.compile(
            r"^\[pid [0-9]+\] mkdir\(\"%s/lib/python.*/site-packages/([a-zA-Z][a-zA-Z0-9_-]+)\", 0777\) = 0"
            % re.escape(venv_directory)
        )

    @staticmethod
    def path_access(path: str) -> Pattern:
        return re.compile(
            r"^\[pid [0-9]+\] (statx|openat|access)\(AT_FDCWD, \"(%s).*$" % path
        )

    @classmethod
    def compile_rules(cls, home_directory:str) -> List[Pattern]:
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
            "/.aws",
            "/.aws/credentials",
            "/.aws/config",
        ]

        rules = []
        for directory in home_directories:
            for relative_path in relative_pathes:
                rules.append(cls.path_access(directory + relative_path))

        return rules

    def __init__(self, home_directory:str, venv_directory: str) -> None:
        self.package_rule = self.compile_paracke_rule(venv_directory)
        self.rules = self.compile_rules(home_directory)


    def identify_resource(self, line:str) -> Optional[str]:
        if match := self.package_rule.match(line):
            return match.groups()[0]

    def match(self, line:str) -> Optional[str]:
        for rule in self.rules:
            if match := rule.match(line):
                return match.groups()[1]

class StraceScanner:
    def __init__(self, rule_set: RuleSet, event_handler: Callable[[str, str], None]) -> None:
        self.rule_set = rule_set
        self.event_handler = event_handler
        self.resource = ''

    def scan(self, lines: Iterator):
        for line in lines:
            if resource := self.rule_set.identify_resource(line):
                self.resource = resource
                continue

            if match := self.rule_set.match(line):
                self.event_handler(self.resource, match)
