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


class UploadVerificationFailedError(Exception):
    pass


class RequirementsError(Exception):
    pass
