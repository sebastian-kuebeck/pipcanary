import re
import unittest

from typing import List

from pipcanary.strace_scanner import (
    StraceCredentialsExfiltrationRuleSet,
    ScannerObserver,
    Finding,
    StraceScanner,
)


class StraceCredentialsExfiltrationRuleSetTest(unittest.TestCase):
    def setUp(self) -> None:
        self.rule_set = StraceCredentialsExfiltrationRuleSet(
            "/testuser", "/tmp/tmp.tFxEKCJMPB-pipcanary"
        )

    def test_identify_resource_during_install(self) -> None:
        finding = self.rule_set.identify_resource(
            '[pid 210676] mkdir("/tmp/tmp.tFxEKCJMPB-pipcanary/lib/python3.10/site-packages/tox", 0777) = 0'
        )
        self.assertEqual("tox", finding)

    def test_identify_resource_during_load(self) -> None:
        finding = self.rule_set.identify_resource("Package: tox")
        self.assertEqual("tox", finding)

    def test_access_pattern(self) -> None:
        path = "/root/.ssh"
        pattern = re.compile(
            r"^\[pid [0-9]+\] (statx|openat|access)\(AT_FDCWD, \"(%s).*$" % path
        )
        match = pattern.match(
            '[pid 420784] statx(AT_FDCWD, "/root/.ssh", AT_STATX_SYNC_AS_STAT|AT_SYMLINK_NOFOLLOW|AT_NO_AUTOMOUNT, STATX_MODE|STATX_NLINK|STATX_UID'
        )
        self.assertTrue(match)
        assert match
        self.assertEqual("/root/.ssh", match.groups()[1])

    def test_match_ssh(self) -> None:
        finding = self.rule_set.match(
            "any",
            '[pid 420784] statx(AT_FDCWD, "/root/.ssh", AT_STATX_SYNC_AS_STAT|AT_SYMLINK_NOFOLLOW|AT_NO_AUTOMOUNT, STATX_MODE|STATX_NLINK|STATX_UID',
        )
        assert finding
        self.assertEqual("/root/.ssh", finding.indication)
        self.assertEqual("any", finding.package)


class TestScannerObserver(ScannerObserver):
    __test__ = False

    def __init__(self) -> None:
        self.resources: List[str] = []
        self.findings: List[Finding] = []

    def resource_identified(self, resource: str):
        self.resources.append(resource)

    def match_detected(self, finding: Finding):
        self.findings.append(finding)


class StraceScannerTest(unittest.TestCase):
    def setUp(self):
        rule_set = StraceCredentialsExfiltrationRuleSet(
            "/testuser", "/tmp/tmp.tFxEKCJMPB-pipcanary"
        )
        self.observer = TestScannerObserver()
        self.scanner = StraceScanner(rule_set, self.observer, None)

    def test_scan(self):
        self.scanner.scan(
            iter(
                [
                    "Package: any",
                    '[pid 420784] statx(AT_FDCWD, "/root/.ssh", AT_STATX_SYNC_AS_STAT|AT_SYMLINK_NOFOLLOW|AT_NO_AUTOMOUNT, STATX_MODE|STATX_NLINK|STATX_UID',
                ]
            )
        )
        self.assertEqual(1, len(self.observer.resources))
        self.assertEqual(1, len(self.observer.findings))

        resource = self.observer.resources[0]
        finding = self.observer.findings[0]

        self.assertEqual("any", resource)
        self.assertEqual(resource, finding.package)
        self.assertEqual("/root/.ssh", finding.indication)
