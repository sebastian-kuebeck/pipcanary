import os
import json
import unittest
from typing import Optional, List
from datetime import datetime, timedelta

from pipcanary.packages import (
    PackageSource,
    Packages,
    PackageInfo,
    Package,
    PackageCheckObserver,
    PackageSelection,
)


class TestPackageSource(PackageSource):
    __test__ = False

    sample_package_info_path = os.path.join(
        os.path.dirname(__file__), "pip_response_encab.json"
    )

    def download_package_info(self, package_name: str) -> Optional[PackageInfo]:
        if package_name == "encab":
            with open(self.sample_package_info_path, "rb") as f:
                return PackageInfo.from_json(json.load(f))


class TestPackageInfo(unittest.TestCase):
    def setUp(self) -> None:
        self.source = TestPackageSource()
        info = self.source.download_package_info("encab")
        assert info
        self.info = info

    def test_releases(self):
        self.assertEqual(19, len(self.info.releases))

    def test_latest_version(self):
        self.assertEqual("1.0.4", self.info.latest_version)

    def test_last_upload_date(self):
        self.assertEqual(
            datetime.fromisoformat("2026-03-22T10:55:24"),
            self.info.latest_upload_date("1.0.4"),
        )


class TestPackage(unittest.TestCase):
    def setUp(self) -> None:
        self.package = Package.from_json(
            {"name": "encab", "version": "1.0.4"}, TestPackageSource()
        )

    def test_latest_upload_date(self):
        self.assertEqual(
            datetime.fromisoformat("2026-03-22T10:55:24"),
            self.package.latest_upload_date,
        )

    def test_latest_possible_upload(self):
        upload = self.package.latest_possible_upload(
            datetime.fromisoformat("2025-11-24T14:19:19")
        )
        assert upload
        self.assertEqual("1.0.3", upload.version)


class TestPackageSelection(unittest.TestCase):

    def test_default_selection(self):
        now = datetime.fromisoformat("2026-03-29T10:55:24")
        selection = PackageSelection(current_time=now)
        self.assertTrue(
            now - timedelta(days=PackageSelection.COOL_DOWN_PHASE_DAYS),
            selection.max_upload_time("any"),
        )

    def test_custom_selection(self):
        now = datetime.fromisoformat("2026-03-29T10:55:24")
        selection = PackageSelection(cool_down_phase_days=2, current_time=now)
        self.assertTrue(
            now - timedelta(days=2),
            selection.max_upload_time("any"),
        )

    def test_general_max_upload_time(self):
        now = datetime.fromisoformat("2026-03-29T10:55:24")
        selection = PackageSelection("2026-03-29T10:55:24")
        self.assertEqual(now, selection.max_upload_time("any"))

    def test_specific_max_upload_time(self):
        now = datetime.fromisoformat("2026-03-29T10:55:24")
        selection = PackageSelection(
            "2026-03-29T10:55:24", allowed_upload_times="encab<=2026-03-29T10:55:24"
        )
        self.assertEqual(now, selection.max_upload_time("any"))


class TestPackageCheckObserver(PackageCheckObserver):
    __test__ = False

    def __init__(self) -> None:
        self.not_found: List[Package] = []
        self.too_recently: List[Package] = []

    def package_not_found(self, package: Package):
        self.not_found.append(package)

    def package_upload_too_recently(
        self, package: Package, upload_time: datetime, latest_upload_time: datetime
    ):
        self.too_recently.append(package)


class TestPackages(unittest.TestCase):

    def setUp(self) -> None:
        self.observer = TestPackageCheckObserver()
        self.packages = Packages(TestPackageSource(), self.observer)
        self.packages.load(
            [
                {"name": "encab", "version": "1.0.4"},
                {"name": "unknown", "version": "0.0.1"},
            ]
        )
        self.selection = PackageSelection(
            current_time=datetime.fromisoformat("2026-03-29T10:55:24")
        )

    def test_load(self):
        self.assertEqual(2, len(self.packages.packages))

    def test_check(self):
        too_recent_packages = self.packages.check_uploads(self.selection)
        self.assertEqual(0, len(too_recent_packages))
        self.assertEqual(1, len(self.observer.not_found))
        self.assertEqual(0, len(self.observer.too_recently))

    def test_check_too_recently(self):
        self.selection.current_time = datetime.fromisoformat("2025-11-24T14:19:19")
        too_recent_packages = self.packages.check_uploads(self.selection)
        self.assertEqual(1, len(too_recent_packages))
