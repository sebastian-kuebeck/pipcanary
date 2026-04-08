import re
import unittest

from pipcanary.strace_scanner import (
    StraceCredentialsExfiltrationRuleSet,
    ScannerObserver,
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
            '[pid 420784] statx(AT_FDCWD, "/root/.ssh", AT_STATX_SYNC_AS_STAT|AT_SYMLINK_NOFOLLOW|AT_NO_AUTOMOUNT, STATX_MODE|STATX_NLINK|STATX_UID'
        )
        self.assertEqual("/root/.ssh", finding)


class TestScannerObserver(ScannerObserver):
    __test__ = False

    def __init__(self, pid: int) -> None:
        self.pid = pid

    def resource_identified(self, resource: str):
        pass

    def match_detected(self, resource: str, pattern: str):
        pass


class StraceScannerTest(unittest.TestCase):
    pass
