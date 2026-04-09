import sys
import re
import io

from typing import Iterator, Optional, List, Dict, Any
from abc import ABC, abstractmethod
from re import Pattern

RULE_SET = [
    {
        "patterns": [
            "/proc/1/comm",
            "/proc/1/cgroup",
        ],
        "designation": "root_directory",
        "description": "Namespace detection.",
        "explanation": "The package might be trying to figure out if it is running in a virual environment. This is very unusual for a legitimate package so it's a strong indicator for malware.",
    },
    {
        "patterns": [
            "/.ssh",
            "/.ssh/id_rsa",
            "/.ssh/id_ed25519",
            "/.ssh/id_ecdsa",
            "/.ssh/id_dsa",
            "/.ssh/authorized_keys",
            "/.ssh/known_hosts",
            "/.ssh/config",
        ],
        "designation": "home_directories",
        "description": "SSH private key exfiltration.",
        "explanation": "The package might be trying to steal your Secure Shell private keys.",
    },
    {
        "patterns": [
            "/.git-credentials",
            "/.gitconfig",
        ],
        "designation": "home_directories",
        "description": "GIT private key exfiltration.",
        "explanation": "The package might be trying to steal your Git credentials.",
    },
    {
        "patterns": [
            "/.aws",
            "/.aws/credentials",
            "/.aws/config",
        ],
        "designation": "home_directories",
        "description": "AWS private key exfiltration.",
        "explanation": "The package might be trying to steal your AWS credentials.",
    },
    {
        "patterns": [
            "/.config/gcloud",
        ],
        "designation": "home_directories",
        "description": "Google Cloud private key exfiltration.",
        "explanation": "The package might be trying to steal your Google Cloud credentials.",
    },
    {
        "patterns": [
            "/.npmrc",
        ],
        "designation": "home_directories",
        "description": "NPM private key exfiltration.",
        "explanation": "The package might be trying to steal your npm credentials.",
    },
]


class Finding:
    def __init__(
        self, package: str, indication: str, description: str, explanation: str
    ) -> None:
        self.package = package
        self.indication = indication
        self.description = description
        self.explanation = explanation

    def write(self, out: io.TextIOBase):
        out.write(
            f"Found suspicious access to {self.indication} in package {self.package}.\n\n"
        )
        out.write(f"Description: {self.description}\n")
        out.write(f"Explanation: {self.explanation}\n")


class RuleSet(ABC):
    @abstractmethod
    def identify_resource(self, line: str) -> Optional[str]:
        pass

    @abstractmethod
    def match(self, resource: str, line: str) -> Optional[Finding]:
        pass

    @abstractmethod
    def warnings_or_errors(self, line: str) -> Optional[str]:
        pass


class AccessRule:

    def __init__(
        self, description: str, patterns: List[str], designation: str, explanation: str
    ) -> None:
        self.description = description
        self.patterns = patterns
        self.designation = designation
        self.explanation = explanation
        self._regex_patterns = []

    @classmethod
    def from_dict(cls, data: Dict[str, Any]):
        description = data["description"]
        patterns = data["patterns"]
        designation = data["designation"]
        explanation = data["explanation"]

        assert isinstance(description, str)
        assert isinstance(patterns, list)
        assert isinstance(designation, str)
        assert isinstance(explanation, str)

        return cls(description, patterns, designation, explanation)

    @staticmethod
    def path_access(path: str) -> Pattern:
        return re.compile(
            r"^\[pid [0-9]+\] (statx|openat|access)\(AT_FDCWD, \"(%s).*$" % path
        )

    def compile(self, home_directory: str):
        self._regex_patterns = []
        match self.designation:
            case "root_directory":
                for path in self.patterns:
                    self._regex_patterns.append(self.path_access(path))
            case "home_directories":
                home_directories = ["/root", home_directory]
                for directory in home_directories:
                    for relative_path in self.patterns:
                        self._regex_patterns.append(
                            self.path_access(directory + relative_path)
                        )

    def match(self, package: str, line: str) -> Optional[Finding]:
        for rule in self._regex_patterns:
            if match := rule.match(line):
                return Finding(
                    package, match.groups()[1], self.description, self.explanation
                )


class StraceCredentialsExfiltrationRuleSet(RuleSet):
    STRACE_PREFIXES = [
        "execve",
        "access",
        "openat",
        "newfstatat",
        "stat",
        "statfs",
        "readlink",
        "rmdir",
        "mkdir",
        "unlink",
        "lstat",
        "getcwd",
        "{st_mode=",
        "+++",
        "---",
        "strace: Process",
        "[pid",
        ")",
        "Package: "
    ]

    @classmethod
    def compile_strace_prefixes(cls) -> Pattern:
        return re.compile(
            r"^%s" % "|".join([f"({re.escape(p)})" for p in cls.STRACE_PREFIXES])
        )

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
    def compile_rules(cls, home_directory: str) -> List[AccessRule]:
        rules = []
        for rule_data in RULE_SET:
            rule = AccessRule.from_dict(rule_data)
            rule.compile(home_directory)
            rules.append(rule)
        return rules

    def __init__(self, home_directory: str, venv_directory: str) -> None:
        self.package_rule = self.compile_package_rule(venv_directory)
        self.rules = self.compile_rules(home_directory)
        self.strace_prefix_pattern = self.compile_strace_prefixes()

    def identify_resource(self, line: str) -> Optional[str]:
        if line.startswith("Package: "):
            return line[9:].strip()

        if match := self.package_rule.match(line):
            return match.groups()[0]

    def match(self, resource: str, line: str) -> Optional[Finding]:
        for rule in self.rules:
            if finding := rule.match(resource, line):
                return finding

    def warnings_or_errors(self, line: str) -> Optional[str]:
        if not self.strace_prefix_pattern.match(line):
            return line


class ScannerObserver(ABC):
    @abstractmethod
    def resource_identified(self, resource: str):
        pass

    @abstractmethod
    def match_detected(self, finding: Finding):
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
                self.observer.resource_identified(resource)
                self.resource = resource
                continue

            if finding := self.rule_set.match(self.resource, line):
                self.observer.match_detected(finding)

    def scan(self, lines: Iterator):
        if self.trace_file:
            with open(self.trace_file, "w") as fp:
                self._scan_lines(lines, fp)
        else:
            self._scan_lines(lines)
