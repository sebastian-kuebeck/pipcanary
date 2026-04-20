import os
import subprocess
import signal
import tempfile
import json
import shutil
import time
import argparse
import logging

from subprocess import CalledProcessError
from typing import List, Dict, Any, Optional
from argparse import ArgumentParser
from datetime import datetime

from .logging import set_up_logging, LOG_LEVELS

from .errors import (
    ExitCodes,
    InvalidArgumentError,
    ScanFailedError,
    AuditFailedError,
    PackageDownloadError,
    RequirementsError,
)

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

    def version_is_vulnerable(self, info: VersionInfo):
        remaining_vulns = list(info.vulnerabilities(self._selection.ignore_vulns))
        vulns_ignored = len(list(info.vulnerabilities())) - len(remaining_vulns)
        remaining_vulns_listed = ", ".join([str(v) for v in remaining_vulns])

        if vulns_ignored:
            logger.error(
                f"Package {str(info.version)} has known vulnerabilities: {remaining_vulns_listed}. {vulns_ignored} vulnerabilities ignored."
            )
        else:
            logger.error(
                f"Package {str(info.version)} has known vulnerabilities: {remaining_vulns_listed}."
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
                vulns = ", ".join([str(v) for v in info.vulnerabilities()])
                message += f"  - The next suitable release {package.name}: {upload.version} has known vulnerabilities though: {vulns}\n"
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
    prog="PipCanary", description="Detects supply chain attacks in python dependencies"
)

parser.add_argument(
    "-r", "--requirement", help=("The requirements file, usually requirements.txt.")
)
parser.add_argument(
    "-p",
    "--project",
    help=(
        "The project file in TOML format. Usually pyproject.toml. "
        "If neither -p or -r are set, ./pyproject.toml or if not exists ./requirements.txt is scanned."
    ),
)

parser.add_argument(
    "--max-upload-time",
    help=(
        "Maximum upload time for all packages (ISO 8601 date and time format). "
        "Example: --max-upload-time='2026-04-07T07:43:51+0000'"
    ),
)
parser.add_argument(
    "-c",
    "--cool-down-phase-days",
    help=("Cool-down phase for packages in days for new package uploads. Default: 7"),
)
parser.add_argument(
    "-a",
    "--allow-upload-time",
    action="append",
    help=(
        "Maximum upload time for a single package (ISO 8601 date and time format). "
        "Example: --allow-upload-time='requests<=2026-04-07T07:43:51+0000"
    ),
)

parser.add_argument(
    "-d",
    "--additional-directory",
    help=(
        "Additional directory mapped into the sandbox while scanning"
        "Make sure this directory does not contain sensitive information!"
    ),
)

parser.add_argument(
    "-t",
    "--trace-file",
    help=("The trace file for further analysis"),
)

parser.add_argument(
    "--sandbox",
    help=(
        "Run with sandbox (default). No sandbox might be safe if you are already running within a sandbox!"
    ),
    action=argparse.BooleanOptionalAction,
    default=True,
)

parser.add_argument(
    "--do-not-scan",
    action="append",
    help=("Add packages that should not be scanned"),
)

parser.add_argument(
    "-i",
    "--index-url",
    help=("URL to PyPi compatible repository"),
)

parser.add_argument(
    "--extra-index-url",
    help=("Extra URL to PyPi compatible repository"),
)

parser.add_argument(
    "--ignore-vuln",
    action="append",
    help=("Ignore the given vulnerability"),
)

parser.add_argument(
    "--log-level",
    help=("The log level. Supported levels are: %s" % (", ".join(LOG_LEVELS))),
    default="INFO",
)


def scan_packages(
    requirements: Requirements,
    additional_directory: Optional[str],
    trace_file: Optional[str],
    sandbox: bool,
    pip_options: PipOptions,
) -> List[Dict[str, Any]]:
    home_directory = os.environ["HOME"]

    if sandbox:
        check_command("bwrap", ["sh", "-c", "bwrap --version 1>/dev/null"])

    env = {**dict(os.environ), "PIPCANARY_PIP_OPTIONS": pip_options.encode_for_shell()}

    if additional_directory:
        env["PIPCANARY_ADDITIONAL_DIRECTORY"] = os.path.abspath(additional_directory)

    command = ["sh", SCAN_SCRIPT_SANDBOXED if sandbox else SCAN_SCRIPT]

    requirements_file = requirements.write_to_temporary_file()
    env["PIPCANARY_REQUIREMENTS_FILE"] = requirements_file

    venv_directory = tempfile.mkdtemp(suffix="-pipcanary")
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
            % (len(requirements.requirements))
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
            % (", ".join([str(v.version) for v in report.vulnerable_versions]))
        )

    if report.too_recent_packages:
        message += "  - The following package(s) were uploaded too recently: %s.\n" % (
            ", ".join([p.name for p in report.too_recent_packages])
        )

    if report.hasFindings():
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
    args = parser.parse_args()

    if args.log_level == "DEBUG":
        log_format = "%(asctime)s - %(levelname)s - %(message)s"
    else:
        log_format = "%(message)s"

    set_up_logging(log_format, args.log_level)

    check_package("venv", ["sh", "-c", "python3 -m venv --help 1>/dev/null"])
    check_command("strace", ["sh", "-c", "strace -V 1>/dev/null"])

    try:
        requirement_file = args.requirement
        project_file = args.project

        pip_options = PipOptions(args.index_url, args.extra_index_url)

        if requirement_file and project_file:
            raise InvalidArgumentError("Either --requirement or --project but not both")

        if not requirement_file and not project_file:
            if os.path.exists("pyproject.toml"):
                project_file = "pyproject.toml"
                logger.info("Using ./pyproject.toml")
            elif os.path.exists("requirements.txt"):
                requirement_file = "requirements.txt"
                logger.info("Using ./requirements.txt")

        if project_file:
            requirements = Requirements.from_project_file(project_file)
        else:
            requirements = Requirements.from_requirements_file(requirement_file)

        requirements_to_audit = requirements.skip_packages(args.do_not_scan or [])

        trace_file = args.trace_file
        selection = AuditSelection(
            max_upload_time=args.max_upload_time,
            cool_down_phase_days=args.cool_down_phase_days,
            allowed_upload_times=args.allow_upload_time,
            ignore_vulns=args.ignore_vuln,
        )
        additional_directory = args.additional_directory
        sandbox = args.sandbox

        if not requirement_file:
            requirement_file = os.path.join(os.path.curdir, "requirements.txt")

        if not os.path.exists(requirement_file):
            raise InvalidArgumentError(
                "Requirements file %s does not exist" % requirement_file
            )

        packages = scan_packages(
            requirements_to_audit,
            additional_directory,
            trace_file,
            sandbox,
            pip_options,
        )
        report = audit_packages(packages, selection, pip_options)

        if not report.ignored_vulns:
            logger.info("All packages appear to be safe!")
        else:
            logger.info("%d vulnerabilities ignored." % len(report.ignored_vulns))
    except (InvalidArgumentError, RequirementsError) as e:
        logger.error(str(e))
        exit(ExitCodes.INVAID_ARGUMENT)
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
