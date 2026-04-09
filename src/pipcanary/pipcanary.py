import sys
import os
import subprocess
import signal
import tempfile
import json
import shutil
import time
import argparse

from subprocess import CalledProcessError
from typing import List, Dict, Any, Optional
from argparse import ArgumentParser
from datetime import datetime

from .requirements import Requirements, RequirementsError

from .strace_scanner import (
    StraceScanner,
    StraceCredentialsExfiltrationRuleSet,
    ScannerObserver,
    Finding,
)

from .packages import (
    Packages,
    PypiPackageSource,
    PackageCheckObserver,
    Package,
    PackageDownloadError,
    PackageSelection,
    PackageAgumentError,
)


class InvalidArgumentError(Exception):
    pass


class ScanFailedError(Exception):
    def __init__(self, rc: int, message: str) -> None:
        super().__init__(message)
        self.rc = rc


class UploadVerificationFailedError(Exception):
    pass


class SuspiciousAccessDetected(Exception):
    def __init__(self, finding: Finding) -> None:
        super().__init__(finding.description)
        self.finding = finding


class AlertingScannerObserver(ScannerObserver):

    def resource_identified(self, resource: str):
        print("Scanning package activity: %s..." % resource)

    def match_detected(self, finding: Finding):
        raise SuspiciousAccessDetected(finding)


class PrintingPackageCheckObserver(PackageCheckObserver):

    def package_not_found(self, package: Package):
        print(f"Package {package.name} not found on pypi")

    def package_upload_too_recently(
        self, package: Package, upload_time: datetime, latest_upload_time: datetime
    ):
        print(
            f"""Package {package.name} {package.version} was updated too recently: {upload_time.isoformat()}. 
It might be safer to use an older version."""
        )
        upload = package.latest_possible_upload(latest_upload_time)
        if upload:
            print(
                f"""Consider {package.name}<={upload.version} or earlier and check for potential known vulnerabilities of this version.
If you are certain that the latest upload is safe, add the following argument...
--allow-upload-time='{package.name}<={upload_time.isoformat()}'
"""
            )
        else:
            print("No suitable version uploaded yet.")


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


def scan_packages(
    requirements: Requirements,
    additional_directory: Optional[str],
    trace_file: Optional[str],
    sandbox: bool,
) -> List[Dict[str, Any]]:
    home_directory = os.environ["HOME"]

    if sandbox:
        check_command("bwrap", ["sh", "-c", "bwrap --version 1>/dev/null"])

    env = {
        **dict(os.environ),
    }

    if additional_directory:
        env["PIPCANARY_ADDITIONAL_DIRECTORY"] = os.path.abspath(additional_directory)

    command = ["sh", SCAN_SCRIPT_SANDBOXED if sandbox else SCAN_SCRIPT]

    requirements_file = requirements.write_to_temporary_file()
    env["REQUIREMENTS_FILE"] = requirements_file

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

        process = subprocess.Popen(command, stderr=subprocess.PIPE, text=True, env=env)

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


def check_package_uploads(
    package_list: List[Dict[str, Any]], selection: PackageSelection
):
    print("Checking the most recent package uploads...\n")
    packages = Packages(PypiPackageSource(), PrintingPackageCheckObserver())
    packages.load(package_list)
    recent_packages = packages.check_uploads(selection)

    if recent_packages:
        raise UploadVerificationFailedError(
            "The following packages were uploaded too recently: %s"
            % (", ".join([p.name for p in recent_packages]))
        )


def check_command(command: str, test_command: List[str]):
    try:
        subprocess.check_call(test_command)
    except CalledProcessError:
        print("Required command %s not found!" % command)
        exit(-1)


def check_package(package: str, test_command: List[str]):
    try:
        subprocess.check_call(test_command)
    except CalledProcessError:
        print("Required python package %s not found!" % package)
        exit(-1)


def pipcanary():
    args = parser.parse_args()
    check_package("venv", ["sh", "-c", "python3 -m venv --help 1>/dev/null"])
    check_command("strace", ["sh", "-c", "strace -V 1>/dev/null"])

    try:
        requirement_file = args.requirement
        project_file = args.project

        if requirement_file and project_file:
            raise InvalidArgumentError("Either --requirement or --project but not both")

        if not requirement_file and not project_file:
            if os.path.exists("pyproject.toml"):
                project_file = "pyproject.toml"
                print("Using ./pyproject.toml")
            elif os.path.exists("requirements.txt"):
                requirement_file = "requirements.txt"
                print("Using ./requirements.txt")

        if project_file:
            requirements = Requirements.from_project_file(project_file)
        else:
            requirements = Requirements.from_requirements_file(requirement_file)

        do_not_scan = args.do_not_scan
        if do_not_scan:
            requirements.skip_packages(do_not_scan)

        trace_file = args.trace_file
        selection = PackageSelection(
            args.max_upload_time, args.cool_down_phase_days, args.allow_upload_time
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
            requirements, additional_directory, trace_file, sandbox
        )
        check_package_uploads(packages, selection)
        print("All packages appear to be safe!")
    except (InvalidArgumentError, PackageAgumentError, RequirementsError) as e:
        print(str(e), file=sys.stderr)
        exit(1)
    except ScanFailedError as e:
        print(str(e), file=sys.stderr)
        exit(2)
    except PackageDownloadError as e:
        print(
            "Failed to download package information for %s: %s"
            % (e.package_name, str(e)),
            file=sys.stderr,
        )
        exit(3)
    except UploadVerificationFailedError as e:
        print(str(e), file=sys.stderr)
        exit(4)
    except SuspiciousAccessDetected as e:
        print(file=sys.stderr)
        e.finding.write(sys.stderr)  # type: ignore
        disclaimer = """
This could be dangerous!!!
Don't install this package under any circumstances until you know for sure that this is a false positive!
In doubt, contact the package maintainers!
"""
        print(disclaimer, file=sys.stderr)
        exit(5)

    except KeyboardInterrupt:
        print("PipCanary was interrupted.")


if __name__ == "__main__":
    pipcanary()
