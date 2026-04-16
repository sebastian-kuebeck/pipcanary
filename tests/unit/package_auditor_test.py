import os
import json
import unittest
from typing import Optional, List
from datetime import datetime, timedelta

from pipcanary.package_auditor import (
    PackageSource,
    PackageAuditor,
    PackageInfo,
    Package,
    PackageAuditObserver,
    AuditSelection,
    PipOptions,
    Version,
    VersionInfo,
)


class TestPackageSource(PackageSource):
    __test__ = False

    sample_package_info_pathes = {
        "pygments": os.path.join(os.path.dirname(__file__), "pygments.json")
    }

    sample_version_info_pathes = {
        "pygments:2.19.0": os.path.join(
            os.path.dirname(__file__), "pygments-2.19.0.json"
        ),
        "pygments:2.20.0": os.path.join(
            os.path.dirname(__file__), "pygments-2.20.0.json"
        ),
    }

    def download_package_info(self, package_name: str) -> Optional[PackageInfo]:
        path = self.sample_package_info_pathes.get(package_name)
        if path:
            with open(path, "rb") as f:
                return PackageInfo.from_json(json.load(f))

    def download_version_info(self, version: Version) -> Optional[VersionInfo]:
        version_id = str(version)
        path = self.sample_version_info_pathes.get(version_id)
        if path:
            with open(path, "rb") as f:
                return VersionInfo.from_json(json.load(f))


class TestPackageInfo(unittest.TestCase):
    def setUp(self) -> None:
        self.source = TestPackageSource()
        info = self.source.download_package_info("pygments")
        assert info
        self.info = info

    def test_releases(self):
        self.assertEqual(68, len(self.info.releases))

    def test_latest_version(self):
        self.assertEqual("2.20.0", self.info.latest_version)

    def test_last_upload_date(self):
        self.assertEqual(
            datetime.fromisoformat("2026-03-29T13:29:33"),
            self.info.latest_upload_date("2.20.0"),
        )


class TestVersionInfo(unittest.TestCase):
    def setUp(self) -> None:
        self.source = TestPackageSource()
        info = self.source.download_version_info(Version("pygments", "2.19.0"))
        assert info
        self.info = info

    def test_vulnerability_ids(self):
        self.assertEqual(["GHSA-5239-wwwm-4pmq"], self.info.vulnerability_ids())

    def test_vulnerability_ids_ignored(self):
        self.assertEqual([], self.info.vulnerability_ids(["GHSA-5239-wwwm-4pmq"]))


class TestPackage(unittest.TestCase):
    def setUp(self) -> None:
        self.package = Package.from_json(
            {"name": "pygments", "version": "2.20.0"}, TestPackageSource()
        )

    def test_latest_upload_date(self):
        self.assertEqual(
            datetime.fromisoformat("2026-03-29T13:29:33"),
            self.package.latest_upload_date,
        )

    def test_latest_possible_upload(self):
        upload = self.package.latest_possible_upload(
            datetime.fromisoformat("2025-11-24T14:19:19")
        )
        assert upload
        self.assertEqual("2.19.2", upload.version)


class TestAuditSelection(unittest.TestCase):

    def test_default_selection(self):
        now = datetime.fromisoformat("2026-03-29T10:55:24")
        selection = AuditSelection(current_time=now)
        self.assertTrue(
            now - timedelta(days=AuditSelection.COOL_DOWN_PHASE_DAYS),
            selection.max_upload_time("any"),
        )

    def test_custom_selection(self):
        now = datetime.fromisoformat("2026-03-29T10:55:24")
        selection = AuditSelection(cool_down_phase_days=2, current_time=now)
        self.assertTrue(
            now - timedelta(days=2),
            selection.max_upload_time("any"),
        )

    def test_general_max_upload_time(self):
        now = datetime.fromisoformat("2026-03-29T10:55:24")
        selection = AuditSelection("2026-03-29T10:55:24")
        self.assertEqual(now, selection.max_upload_time("any"))

    def test_specific_max_upload_time(self):
        now = datetime.fromisoformat("2026-03-29T10:55:24")
        selection = AuditSelection(
            "2026-03-29T10:55:24", allowed_upload_times="encab<=2026-03-29T10:55:24"
        )
        self.assertEqual(now, selection.max_upload_time("any"))


class TestPackageCheckObserver(PackageAuditObserver):
    __test__ = False

    def __init__(self) -> None:
        self.vulnerable: List[VersionInfo] = []
        self.versions_not_found: List[Version] = []
        self.not_found: List[Package] = []
        self.too_recently: List[Package] = []

    def version_is_vulnerable(self, info: VersionInfo):
        self.vulnerable.append(info)

    def version_not_found(self, version: Version):
        self.versions_not_found.append(version)

    def package_not_found(self, package: Package):
        self.not_found.append(package)

    def package_upload_too_recently(
        self, package: Package, upload_time: datetime, latest_upload_time: datetime
    ):
        self.too_recently.append(package)


class TestPackageAuditor(unittest.TestCase):

    def setUp(self) -> None:
        self.observer = TestPackageCheckObserver()
        self.packages = PackageAuditor(TestPackageSource(), self.observer)

    def test_audit(self):
        package_data = [
            {"name": "pygments", "version": "2.20.0"},
            {"name": "unknown", "version": "0.0.1"},
        ]
        self.selection = AuditSelection(
            current_time=datetime.fromisoformat("2026-04-26T10:55:24")
        )
        report = self.packages.audit(self.selection, package_data)

        self.assertEqual(0, len(report.vulnerable_versions))
        self.assertEqual(0, len(report.too_recent_packages))
        self.assertEqual(0, len(report.ignored_vulns))

        self.assertEqual(1, len(self.observer.versions_not_found))
        self.assertEqual(0, len(self.observer.vulnerable))
        self.assertEqual(0, len(self.observer.too_recently))

    def test_audit_with_known_vulns(self):
        package_data = [
            {"name": "pygments", "version": "2.19.0"},
        ]
        self.selection = AuditSelection(
            current_time=datetime.fromisoformat("2026-04-26T10:55:24")
        )
        report = self.packages.audit(self.selection, package_data)
        self.assertEqual(1, len(report.vulnerable_versions))
        self.assertEqual(0, len(report.too_recent_packages))
        self.assertEqual(0, len(report.ignored_vulns))

        self.assertEqual(0, len(self.observer.versions_not_found))
        self.assertEqual(1, len(self.observer.vulnerable))
        self.assertEqual(0, len(self.observer.too_recently))

    def test_audit_too_recently(self):
        package_data = [
            {"name": "pygments", "version": "2.20.0"},
        ]
        self.selection = AuditSelection(
            current_time=datetime.fromisoformat("2026-03-29T13:29:33")
        )
        report = self.packages.audit(self.selection, package_data)
        self.assertEqual(0, len(report.vulnerable_versions))
        self.assertEqual(1, len(report.too_recent_packages))
        self.assertEqual(0, len(report.ignored_vulns))

        self.assertEqual(0, len(self.observer.versions_not_found))
        self.assertEqual(0, len(self.observer.vulnerable))
        self.assertEqual(1, len(self.observer.too_recently))


class TestPipOptions(unittest.TestCase):
    def test_encode_to_shell(self):
        options = PipOptions(
            "http://localhost:3141/root/pypi/+simple/",
            "http://localhost:3141/root/pypi/+test/",
        )
        self.assertEqual(
            "--index-url http://localhost:3141/root/pypi/+simple/ --extra-index-url http://localhost:3141/root/pypi/+test/",
            options.encode_for_shell(),
        )

    def test_pip_environment(self):
        options = PipOptions(
            "http://localhost:3141/root/pypi/+simple/",
            "http://localhost:3141/root/pypi/+test/",
        )
        self.assertEqual(
            {
                "PIP_INDEX_URL": "http://localhost:3141/root/pypi/+simple/",
                "PIP_EXTRA_INDEX_URL": "http://localhost:3141/root/pypi/+test/",
            },
            options.pip_environment(),
        )
