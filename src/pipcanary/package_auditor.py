import logging
import json

from typing import Dict, Any, Optional, List, Union, Iterable
from urllib.request import urlopen
from urllib.error import URLError, HTTPError
from datetime import datetime, timedelta
from abc import ABC, abstractmethod
from shlex import quote

from .errors import InvalidArgumentError, PackageDownloadError

logger = logging.getLogger(__name__)


class PackageVersion:
    def __init__(self, name: str, version: str) -> None:
        self.name = name
        self.version = version

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> "PackageVersion":
        return cls(
            data["name"],
            data["version"],
        )

    def __str__(self) -> str:
        return f"{self.name}:{self.version}"


class Upload:
    def __init__(self, version: str, upload_time: datetime, yanked: bool) -> None:
        self.version = version
        self.upload_time = upload_time
        self.yanked = yanked

    @classmethod
    def from_json(cls, version: str, data: Dict[str, Any]) -> "Upload":
        upload_time = data["upload_time"]
        yanked = data.get("yanked", False)
        return cls(version, datetime.fromisoformat(upload_time), yanked)


class VulnerabilityId:
    def __init__(self, value) -> None:
        self.value = value

    def __eq__(self, value: object) -> bool:
        return self.value.lower() == str(value).lower()

    def __hash__(self) -> int:
        return hash(self.value.lower())

    def __repr__(self) -> str:
        return self.value

    def __str__(self) -> str:
        return self.value


class Vulnerability:
    def __init__(
        self,
        id: str,
        aliases: List[str],
        summary: Optional[str],
        description: Optional[str],
        link: Optional[str],
        published: Optional[datetime],
        fixed_versions: List[str],
    ) -> None:
        self.id = VulnerabilityId(id)
        self.aliases = set([VulnerabilityId(a) for a in aliases])
        self.summary = summary
        self.description = description
        self.link = link
        self.published = published
        self.fixed_versions = fixed_versions

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> "Vulnerability":
        published = data.get("published")
        return cls(
            data["id"],
            data.get("aliases", []),
            data.get("summary"),
            data.get("description"),
            data.get("link"),
            datetime.fromisoformat(published) if published else None,
            data.get("fixed_in", []),
        )

    def __str__(self) -> str:
        if not self.fixed_versions:
            return str(self.id)

        return "%s (%s)" % (
            str(self.id),
            "fixed in %s" % ", ".join(self.fixed_versions),
        )

    def __contains__(self, ids):
        if not hasattr(ids, "__iter__"):
            return False

        if self.id in ids:
            return True

        if self.aliases.intersection(ids):
            return True

        return False

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, Vulnerability):
            return False
        return self.id == value.id

    def __hash__(self) -> int:
        return hash(self.id)


class VersionInfo:
    def __init__(
        self, package_version: PackageVersion, vulnerabilities: List[Vulnerability]
    ) -> None:
        self.version = package_version
        self._vulnerabilities = vulnerabilities

    def vulnerabilities(
        self, ignored_ids: Optional[Iterable[str]] = None
    ) -> Iterable[Vulnerability]:
        if not ignored_ids:
            yield from self._vulnerabilities
        else:
            for vuln in self._vulnerabilities:
                if ignored_ids not in vuln:
                    yield vuln

    @property
    def has_vulnerabilities(self):
        return len(self._vulnerabilities) > 0

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> "VersionInfo":
        info = data["info"]
        vulnerabilities = data["vulnerabilities"]
        return cls(
            PackageVersion.from_json(info),
            [
                Vulnerability.from_json(v)
                for v in vulnerabilities
                if not v.get("withdrawn")
            ],
        )


class Release:
    def __init__(self, version: str, uploads: List[Upload]) -> None:
        self.version = version
        self.uploads = uploads

    @property
    def latest_upload_date(self) -> Optional[datetime]:
        if self.uploads:
            present_uploads = [u.upload_time for u in self.uploads if not u.yanked]
            return max(present_uploads) if present_uploads else None
        else:
            return None

    @classmethod
    def from_json(cls, version: str, data: List[Dict[str, Any]]) -> "Release":
        uploads: List[Upload] = []
        for upload_data in data:
            uploads.append(Upload.from_json(version, upload_data))
        return cls(version, uploads)


class PackageInfo:
    def __init__(
        self, latest_version: Optional[str], releases: Dict[str, Release]
    ) -> None:
        self.latest_version = latest_version
        self.releases = releases

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> "PackageInfo":
        releases: Dict[str, Release] = {}
        for version, release_list in data.get("releases", {}).items():
            releases[version] = Release.from_json(version, release_list)

        latest_version = data["info"]["version"]

        if latest_version:
            return cls(latest_version, releases)
        else:
            return cls(None, {})

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

    @abstractmethod
    def download_version_info(
        self, package_version: PackageVersion
    ) -> Optional[VersionInfo]:
        pass


class PipOptions:
    PYPI_INDEX_URL = "https://pypi.org/pypi/"

    def __init__(
        self, index_url: Optional[str] = None, extra_index_url: Optional[str] = None
    ) -> None:
        self.default_index_url = self.PYPI_INDEX_URL
        self._index_url = index_url
        self._extra_index_url = extra_index_url

    @staticmethod
    def _normalize_url(url: str) -> str:
        if not url.endswith("/"):
            url += "/"
        return url

    @property
    def index_url(self) -> Optional[str]:
        return self._normalize_url(self._index_url) if self._index_url else None

    def pip_environment(self) -> Dict[str, str]:
        env = {}
        if self._index_url:
            env["PIP_INDEX_URL"] = self._index_url

        if self._extra_index_url:
            env["PIP_EXTRA_INDEX_URL"] = self._extra_index_url
        return env

    def encode_for_shell(self) -> str:
        s = ""
        if self._index_url:
            s += "--index-url %s" % quote(self._index_url)
        if self._extra_index_url:
            s += " --extra-index-url %s" % quote(self._extra_index_url)
        return s.strip()


class PypiPackageSource(PackageSource):
    def __init__(self, options: PipOptions) -> None:
        self.options = options
        self._index_url = options.index_url

    def download(self, url: str, package_name) -> Optional[Dict[str, Any]]:
        try:
            logging.debug(
                f"Downloading package metadata for package {package_name} from {url}..."
            )
            response = urlopen(url)  # nosec
            return json.load(response)
        except HTTPError as e:
            if e.code == 404:
                logger.debug(f"Package {package_name} metadata not found at {url}.")
                return None
            else:
                raise PackageDownloadError(package_name, str(e), e)
        except URLError as e:
            raise PackageDownloadError(package_name, str(e), e)

    def download_from_index(
        self, path: str, package_name: str
    ) -> Optional[Dict[str, Any]]:
        if self._index_url:
            try:
                response = self.download(f"{self._index_url}{path}", package_name)
                if response:
                    return response
                else:
                    return self.download(
                        f"{self.options.default_index_url}{path}", package_name
                    )
            except PackageDownloadError:
                logging.warning(
                    f"Failed to retrieve metadata from {self._index_url}. Falling back to {self.options.default_index_url}."
                )
                self._index_url = None
        else:
            return self.download(
                f"{self.options.default_index_url}{path}", package_name
            )

    def download_package_info(self, package_name: str) -> Optional[PackageInfo]:
        package_info_data = self.download_from_index(
            f"{package_name}/json", package_name
        )
        return PackageInfo.from_json(package_info_data) if package_info_data else None

    def download_version_info(
        self, package_version: PackageVersion
    ) -> Optional[VersionInfo]:
        version_info_data = self.download_from_index(
            f"{package_version.name}/{package_version.version}/json",
            str(package_version),
        )
        return VersionInfo.from_json(version_info_data) if version_info_data else None


class Package:
    def __init__(self, name: str, version: str, source: PackageSource) -> None:
        self.name = name
        self.version = version
        self.source = source
        self._info_available = False
        self._info: Optional[PackageInfo] = None

    @classmethod
    def from_json(cls, record: Dict[str, str], source: PackageSource) -> "Package":
        return cls(record["name"], record["version"], source)

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
                if not upload.yanked and upload.upload_time <= latest_upload_time:
                    return upload

    def __str__(self) -> str:
        return f"{self.name} {self.version}"


class PackageAuditObserver(ABC):
    @abstractmethod
    def version_is_vulnerable(self, info: VersionInfo):
        pass

    @abstractmethod
    def version_not_found(self, version: PackageVersion):
        pass

    @abstractmethod
    def package_not_found(self, package: Package):
        pass

    @abstractmethod
    def package_upload_too_recently(
        self, package: Package, upload_time: datetime, latest_upload_time: datetime
    ):
        pass


class AuditSelection:
    COOL_DOWN_PHASE_DAYS = 7

    def __init__(
        self,
        max_upload_time: Optional[str] = None,
        cool_down_phase_days: Optional[int] = None,
        allowed_upload_times: Optional[Union[List[str], str]] = None,
        ignore_vulns: Optional[Union[List[str], str]] = None,
        current_time: Optional[datetime] = None,
    ) -> None:
        self.current_time: datetime = current_time or datetime.now()
        self.cool_down_phase_days = cool_down_phase_days or self.COOL_DOWN_PHASE_DAYS
        try:
            self._max_upload_time: Optional[datetime] = (
                datetime.fromisoformat(max_upload_time) if max_upload_time else None
            )
        except ValueError:
            raise InvalidArgumentError(
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
                raise InvalidArgumentError(
                    "Malformed argument max_upload_time. Expected <package_name><=<max upload time>"
                )
        if isinstance(ignore_vulns, str):
            ignore_vulns = [ignore_vulns]

        self.ignore_vulns = set(ignore_vulns or [])

    def max_upload_time(self, package: str) -> datetime:
        return self._max_upload_time_for.get(package, self._max_upload_time) or (
            self.current_time - timedelta(days=int(self.cool_down_phase_days))
        )


class AuditReport:
    def __init__(
        self,
        vulnerable_versions: List[VersionInfo],
        too_recent_packages: List[Package],
        ignored_vulns: List[Vulnerability],
    ) -> None:
        self.vulnerable_versions = vulnerable_versions
        self.too_recent_packages = too_recent_packages
        self.ignored_vulns = ignored_vulns

    def hasFindings(self) -> bool:
        return len(self.vulnerable_versions) > 0 or len(self.too_recent_packages) > 0


class PackageAuditor:
    def __init__(self, source: PackageSource, observer: PackageAuditObserver) -> None:
        self.source = source
        self.observer: PackageAuditObserver = observer

    def audit(
        self, selection: AuditSelection, version_list: List[Dict[str, str]]
    ) -> AuditReport:
        vulnerable_versions: List[VersionInfo] = []
        too_recent_packages: List[Package] = []
        ignored_vulns: List[Vulnerability] = []

        for version_data in version_list:
            package_version = PackageVersion.from_json(version_data)
            info = self.source.download_version_info(package_version)
            if not info:
                self.observer.version_not_found(package_version)
                continue

            if info.has_vulnerabilities:
                vulns = info.vulnerabilities(selection.ignore_vulns)
                if vulns:
                    self.observer.version_is_vulnerable(info)
                    vulnerable_versions.append(info)
                    continue
                else:
                    ignored_vulns.extend(info.vulnerabilities())

            package = Package.from_json(version_data, self.source)

            upload_time = package.latest_upload_date

            if not upload_time:
                self.observer.package_not_found(package)
                continue

            if upload_time > (
                latest_upload_time := selection.max_upload_time(package.name)
            ):
                self.observer.package_upload_too_recently(
                    package, upload_time, latest_upload_time
                )
                too_recent_packages.append(package)

        return AuditReport(
            vulnerable_versions, too_recent_packages, list(set(ignored_vulns))
        )
