from enum import IntEnum


class ExitCodes(IntEnum):
    OK = 0
    MISSING_REQUIREMENT = -1
    INVAID_ARGUMENT = 1
    SCAN_FAILED = 2
    PACKAGE_DOWNLOAD_FAILED = 3
    AUDIT_FAILED = 4
    SCAN_ALERT = 5


class InvalidArgumentError(Exception):
    pass


class ScanFailedError(Exception):
    def __init__(self, rc: int, message: str) -> None:
        super().__init__(message)
        self.rc = rc


class PackageDownloadError(Exception):
    def __init__(self, package_name: str, msg: str, parent: Exception) -> None:
        super().__init__(msg)
        self.package_name = package_name
        self.parent = parent


class AuditFailedError(Exception):
    pass


class RequirementsError(Exception):
    pass
