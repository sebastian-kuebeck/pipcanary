import os
import subprocess
import signal
import tempfile
import json
import shutil
import time
import logging

from subprocess import CalledProcessError
from typing import List, Dict, Any, Optional
from argparse import ArgumentParser
from datetime import datetime

from .logging import set_up_logging

from .errors import (
    ExitCodes,
    InvalidArgumentError,
    ScanFailedError,
    AuditFailedError,
    PackageDownloadError,
    RequirementsError,
)

from .parameters import PipCanaryParameters

from .requirements import Requirements

from .strace_scanner import (
    StraceScanner,
    StraceCredentialsExfiltrationRuleSet,
    ScannerObserver,
    Finding,
)

from .package_auditor import (
    PackageAuditor,
    PipOptions,
    PackageSource,
    PypiPackageSource,
    PackageAuditObserver,
    Package,
    PackageVersion,
    VersionInfo,
    AuditSelection,
    AuditReport,
)

PIPCANARY_VERSION = "0.1.0"


class SuspiciousAccessDetected(Exception):
    def __init__(self, finding: Finding) -> None:
        super().__init__(finding.description)
        self.finding = finding


logger = logging.getLogger(__name__)


class AlertingScannerObserver(ScannerObserver):

    def resource_identified(self, resource: str):
        logger.info("Scanning package activity: %s..." % resource)

    def match_detected(self, finding: Finding):
        raise SuspiciousAccessDetected(finding)

    def warning_or_error(self, message: str):
        logger.error(message)


class LoggingPackageAuditObserver(PackageAuditObserver):
    def __init__(self, source: PackageSource, selection: AuditSelection) -> None:
        self._source = source
        self._selection = selection

    @staticmethod
    def alliterate(vs: List[Any]):
        return ", ".join([str(v) for v in vs])

    def version_is_vulnerable(self, info: VersionInfo):
        logger.error(
            f"Package {str(info.package_version)} has known vulnerabilities: {self.alliterate(info.vulnerabilities())}."
        )

    def version_not_found(self, version: PackageVersion):
        logger.warning(f"Package {str(version)} not found on pypi")

    def package_not_found(self, package: Package):
        logger.warning(f"Package {package.name} not found on pypi")

    def package_upload_too_recently(
        self, package: Package, upload_time: datetime, latest_upload_time: datetime
    ):
        message = f"Package {package.name} {package.version} was updated too recently: {upload_time.isoformat()}.\n"
        upload = package.latest_possible_upload(latest_upload_time)
        if upload:
            info = self._source.download_version_info(
                PackageVersion(package.name, upload.version)
            )

            if not info:
                message += f"  - There is no security information on PyPi about the next suitable release {package.name}: {upload.version}\n"
            elif info.has_vulnerabilities:
                vulnerabilities = self.alliterate(info.vulnerabilities())
                message += f"  - The next suitable release {package.name}: {upload.version} has known vulnerabilities though: {vulnerabilities}\n"
            else:
                message += f"  - Consider {package.name}<={upload.version} which has no known vulnerabilities\n"

            message += (
                "  - If you are certain that the latest upload is secure, add the following argument: "
                f"--allow-upload-time='{package.name}<={upload_time.isoformat()}'"
            )

        else:
            message += " - No suitable version uploaded yet."

        logger.warning(message)


SCAN_SCRIPT_SANDBOXED = os.path.join(os.path.dirname(__file__), "sbpip_scan.sh")
SCAN_SCRIPT = os.path.join(os.path.dirname(__file__), "spip_scan.sh")

parser = ArgumentParser(
    prog="pipcanary",
    description=f"PipCanary {PIPCANARY_VERSION} detects supply chain attacks and known vulnerabilities in python dependencies",
)

parser.add_argument("--version", action="version", version=PIPCANARY_VERSION)

parameters = PipCanaryParameters()
parameters.add_arguments(parser)


def scan_packages(
    requirements: Requirements,
    sandbox: bool,
    pip_options: PipOptions,
    trace_file: Optional[str] = None,
) -> List[Dict[str, Any]]:
    home_directory = os.environ["HOME"]

    if sandbox:
        check_command("bwrap", ["sh", "-c", "bwrap --version 1>/dev/null"])

    env = {**dict(os.environ), "PIPCANARY_PIP_OPTIONS": pip_options.encode_for_shell()}

    additional_directory = pip_options.additional_directory
    if additional_directory:
        env["PIPCANARY_ADDITIONAL_DIRECTORY"] = os.path.abspath(additional_directory)

    command = ["sh", SCAN_SCRIPT_SANDBOXED if sandbox else SCAN_SCRIPT]

    requirements_file = requirements.write_to_temporary_file()
    env["PIPCANARY_REQUIREMENTS_FILE"] = requirements_file

    temporary_directory = pip_options.temporary_directory
    venv_directory = tempfile.mkdtemp(suffix="-pipcanary", dir=temporary_directory)
    process = None

    try:
        env["PIPCANARY_VIRTUAL_ENV"] = venv_directory

        observer = AlertingScannerObserver()
        scanner = StraceScanner(
            StraceCredentialsExfiltrationRuleSet(home_directory, venv_directory),
            observer,
            trace_file,
        )
        logging.info(
            "Scanning packages for %d requirements..."
            % (len(requirements._requirements))
        )

        if logger.isEnabledFor(logging.DEBUG):
            process = subprocess.Popen(
                command, stderr=subprocess.PIPE, text=True, env=env
            )
        else:
            process = subprocess.Popen(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
        assert process.stderr

        scanner.scan(process.stderr)

        process.wait()

        if process.returncode != 0:
            raise ScanFailedError(
                process.returncode, "Scan failed with rc %d" % process.returncode
            )

        packages_file = os.path.join(venv_directory, "packages.json")
        if not os.path.exists(packages_file):
            raise ScanFailedError(-1, "Scan failed for unknown reason")
        with open(packages_file, "r") as f:
            return json.load(f)
    except SuspiciousAccessDetected as e:
        if process:
            os.kill(process.pid, signal.SIGKILL)
        raise e
    finally:
        for i in range(3):
            try:
                os.remove(requirements_file)
            except OSError:
                time.sleep(i)

        for i in range(3):
            try:
                shutil.rmtree(venv_directory)
            except OSError:
                time.sleep(i)


def audit_packages(
    package_list: List[Dict[str, Any]], selection: AuditSelection, options: PipOptions
) -> AuditReport:
    logging.info("Auditing %d packages..." % len(package_list))
    source = PypiPackageSource(options)
    packages = PackageAuditor(source, LoggingPackageAuditObserver(source, selection))
    report = packages.audit(selection, package_list)

    message = ""

    if report.vulnerable_versions:
        message += (
            "  - Vulnerabilities in the following package(s) were found: %s.\n"
            % (", ".join([str(v.package_version) for v in report.vulnerable_versions]))
        )

    if report.too_recent_packages:
        message += "  - The following package(s) were uploaded too recently: %s.\n" % (
            ", ".join([p.name for p in report.too_recent_packages])
        )

    if report.has_findings():
        raise AuditFailedError(message)

    return report


def check_command(command: str, test_command: List[str]):
    try:
        subprocess.check_call(test_command)
    except CalledProcessError:
        logger.error("Required command %s not found!" % command)
        exit(ExitCodes.MISSING_REQUIREMENT)


def check_package(package: str, test_command: List[str]):
    try:
        subprocess.check_call(test_command)
    except CalledProcessError:
        logger.error("Required python package %s not found!" % package)
        exit(ExitCodes.MISSING_REQUIREMENT)


def pipcanary():
    try:
        parameters.fill(parser.parse_args())

        if parameters.log_level == "DEBUG":
            log_format = "%(asctime)s - %(levelname)s - %(message)s"
        else:
            log_format = "%(message)s"

        set_up_logging(log_format, parameters.log_level)

        check_package("venv", ["sh", "-c", "python3 -m venv --help 1>/dev/null"])
        check_command("strace", ["sh", "-c", "strace -V 1>/dev/null"])

        requirements = parameters.requirements()
        locked_requirement_file = parameters.locked_requirements_file

        pip_options = parameters.pipOptions()
        requirements_to_audit = requirements.skip_packages(parameters.do_not_scan or [])

        if parameters.log_level == "DEBUG":
            logger.debug("Parameters: %s" % parameters.values)
            logger.debug("Requirements_to_audit: %s" % requirements_to_audit.list())

        packages = scan_packages(
            requirements=requirements_to_audit,
            sandbox=parameters.sandbox,
            pip_options=pip_options,
            trace_file=parameters.trace_file,
        )
        report = audit_packages(packages, parameters.auditSelection(), pip_options)

        if not report.ignored_vulns:
            logger.info("All packages appear to be safe!")
        else:
            logger.info("%d vulnerabilities ignored." % len(report.ignored_vulns))

        if locked_requirement_file:
            logging.info(f"Writing locked requirements file: {locked_requirement_file}")
            report.write_locked_requirements(locked_requirement_file)

    except (InvalidArgumentError, RequirementsError) as e:
        logger.error(str(e))
        exit(ExitCodes.INVALID_ARGUMENT)
    except ScanFailedError as e:
        logger.error(str(e))
        exit(ExitCodes.SCAN_FAILED)
    except PackageDownloadError as e:
        logger.error(
            "Failed to download package information for %s: %s"
            % (e.package_name, str(e))
        )
        exit(3)
    except AuditFailedError as e:
        logger.error("Summary:\n" + str(e))
        exit(ExitCodes.AUDIT_FAILED)
    except SuspiciousAccessDetected as e:
        message = f"""
{str(e.finding)}
        
This could be dangerous!!!
Don't install this package under any circumstances until you know for sure that this is a false positive!
In doubt, contact the package maintainers!
"""
        logger.fatal(message)
        exit(ExitCodes.SCAN_ALERT)

    except KeyboardInterrupt:
        logger.info("PipCanary was interrupted.")


if __name__ == "__main__":
    pipcanary()
