import json

from typing import Dict, Any, Optional, List, Union
from urllib.request import urlopen
from urllib.error import URLError, HTTPError
from datetime import datetime, timedelta
from abc import ABC, abstractmethod


class Upload:
    def __init__(self, version: str, upload_time: datetime) -> None:
        self.version = version
        self.upload_time = upload_time

    @staticmethod
    def from_json(version: str, data: Dict[str, Any]) -> "Upload":
        upload_time = data["upload_time"]
        return Upload(version, datetime.fromisoformat(upload_time))


class Release:
    def __init__(self, version: str, uploads: List[Upload]) -> None:
        self.version = version
        self.uploads = uploads

    @property
    def latest_upload_date(self) -> Optional[datetime]:
        if self.uploads:
            return max([u.upload_time for u in self.uploads])
        else:
            return None

    @staticmethod
    def from_json(version: str, data: List[Dict[str, Any]]) -> "Release":
        uploads: List[Upload] = []
        for upload_data in data:
            uploads.append(Upload.from_json(version, upload_data))
        return Release(version, uploads)


class PackageInfo:
    def __init__(
        self, latest_version: Optional[str], releases: Dict[str, Release]
    ) -> None:
        self.latest_version = latest_version
        self.releases = releases

    @staticmethod
    def from_json(data: Dict[str, Any]) -> "PackageInfo":
        releases: Dict[str, Release] = {}
        for version, release_list in data.get("releases", {}).items():
            releases[version] = Release.from_json(version, release_list)

        latest_version = data["info"]["version"]

        if latest_version:
            return PackageInfo(latest_version, releases)
        else:
            return PackageInfo(None, {})

    def latest_upload_date(self, version: str) -> Optional[datetime]:
        if self.latest_version and self.releases:
            release = self.releases.get(version)
            if release:
                return release.latest_upload_date

    @property
    def uploads(self) -> List[Upload]:
        uploads = []
        for _, release in self.releases.items():
            uploads.extend(release.uploads)
        return uploads


class PackageSource(ABC):
    @abstractmethod
    def download_package_info(self, package_name: str) -> Optional[PackageInfo]:
        pass


class PackageDownloadError(Exception):
    def __init__(self, package_name: str, msg: str, parent: Exception) -> None:
        super().__init__(msg)
        self.package_name = package_name
        self.parent = parent


class PypiPackageSource(PackageSource):
    def download_package_info(self, package_name: str) -> Optional[PackageInfo]:
        try:
            response = urlopen(f"https://pypi.org/pypi/{package_name}/json")
            package_info_data = json.load(response)
            return PackageInfo.from_json(package_info_data)
        except HTTPError as e:
            if e.code == 404:
                return None
            else:
                raise PackageDownloadError(package_name, str(e), e)
        except URLError as e:
            raise PackageDownloadError(package_name, str(e), e)


class PackageAgumentError(Exception):
    pass


class Package:
    def __init__(self, name: str, version: str, source: PackageSource) -> None:
        self.name = name
        self.version = version
        self.source = source
        self._info_available = False
        self._info: Optional[PackageInfo] = None

    @staticmethod
    def from_json(record: Dict[str, str], source: PackageSource) -> "Package":
        return Package(record["name"], record["version"], source)

    @property
    def info(self) -> Optional[PackageInfo]:
        if not self._info_available:
            self._info = self.source.download_package_info(self.name)
            self._info_available = True

        return self._info

    @property
    def latest_upload_date(self) -> Optional[datetime]:
        if self.info:
            return self.info.latest_upload_date(self.version)

    def latest_possible_upload(self, latest_upload_time: datetime) -> Optional[Upload]:
        if self.info:
            uploads = sorted(
                self.info.uploads, key=lambda u: u.upload_time, reverse=True
            )
            for upload in uploads:
                if upload.upload_time <= latest_upload_time:
                    return upload

    def __str__(self) -> str:
        return f"{self.name} {self.version}"


class PackageCheckObserver(ABC):
    @abstractmethod
    def package_not_found(self, package: Package):
        pass

    @abstractmethod
    def package_too_recently(
        self, package: Package, upload_time: datetime, latest_upload_time: datetime
    ):
        pass


class PackageSelection:
    COOL_DOWN_PHASE_DAYS = 7

    def __init__(
        self,
        max_upload_time: Optional[str] = None,
        cool_down_phase_days: Optional[int] = None,
        allowed_upload_times: Optional[Union[List[str], str]] = None,
        current_time: Optional[datetime] = None,
    ) -> None:
        self.current_time: datetime = current_time or datetime.now()
        self.cool_down_phase_days = cool_down_phase_days or self.COOL_DOWN_PHASE_DAYS
        try:
            self._max_upload_time: Optional[datetime] = (
                datetime.fromisoformat(max_upload_time) if max_upload_time else None
            )
        except ValueError:
            raise PackageAgumentError(
                "Malformed datetime passed with argument max_upload_time"
            )

        self._max_upload_time_for: Dict[str, datetime] = {}

        if isinstance(allowed_upload_times, str):
            allowed_upload_times = [allowed_upload_times]

        rules = allowed_upload_times or []
        for rule in rules:
            try:
                package, max_upload_time = rule.split("<=")
                self._max_upload_time_for[package] = datetime.fromisoformat(
                    max_upload_time
                )
            except ValueError:
                raise PackageAgumentError(
                    "Malformed argument max_upload_time. Expected <package_name><=<max upload time>"
                )

    def max_upload_time(self, package: str) -> datetime:
        return self._max_upload_time_for.get(package, self._max_upload_time) or (
            self.current_time - timedelta(days=self.cool_down_phase_days)
        )


class Packages:
    def __init__(self, source: PackageSource, observer: PackageCheckObserver) -> None:
        self.source = source
        self.packages: List[Package] = []
        self.observer: PackageCheckObserver = observer

    def load(self, package_list: List[Dict[str, str]]) -> List[Package]:
        for package_data in package_list:
            package = Package(
                package_data["name"], package_data["version"], self.source
            )
            self.packages.append(package)
        return self.packages

    def check_uploads(self, selection: PackageSelection) -> List[Package]:
        recent_packages: List[Package] = []
        for package in self.packages:
            upload_time = package.latest_upload_date

            if not upload_time:
                self.observer.package_not_found(package)
                continue

            if upload_time > (
                latest_upload_time := selection.max_upload_time(package.name)
            ):
                self.observer.package_too_recently(
                    package, upload_time, latest_upload_time
                )
                recent_packages.append(package)
        return recent_packages
