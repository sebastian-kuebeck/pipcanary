import re
import os
import subprocess
import signal
import tempfile
import json
import requests

from requests.exceptions import HTTPError
from typing import Optional, List, Dict, Any
from argparse import ArgumentParser
from datetime import datetime, timedelta


class InvalidArgumentError(Exception):
    pass


class ScanFailedError(Exception):
    def __init__(self, rc: int, message: str) -> None:
        super().__init__(message)
        self.rc = rc


class UploadVerificationFailedError(Exception):
    pass


class SuspiciousAccessDetected(Exception):
    def __init__(self, pid: int, message: str) -> None:
        super().__init__(message)
        self.pid = pid


INSTALL_SCRIPT = os.path.join(os.path.dirname(__file__), "sbpip_scan.sh")
# INSTALL_SCRIPT = os.path.join(os.path.dirname(__file__), 'sbpip_test.sh')

parser = ArgumentParser(
    prog="PipCanary", description="Detects rogue packages in python dependencies"
)

parser.add_argument("-r", "--requirement")

home = os.environ["HOME"]

def path_access(path: str) -> re.Pattern:
    return re.compile(
        rf"^\[pid [0-9]+\] (statx|openat|access)\(AT_FDCWD, \"(%s).*$" % path
    )

homes = ["/root", home]
files = [
    "/.ssh",
    "/.ssh/id_rsa",
    "/.ssh/id_ed25519",
    "/.ssh/id_ecdsa",
    "/.ssh/id_dsa",
    "/.ssh/authorized_keys",
    "/.ssh/known_hosts",
    "/.ssh/config",
    "/.aws",
    "/.aws/credentials",
    "/.aws/config",
]

rules = []
for home in homes:
    for file in files:
        rules.append(path_access(home + file))


def scan_packages(requirement_file: str) -> List[Dict[str, Any]]:
    with tempfile.TemporaryDirectory(suffix="-pipcanary") as tmpdir:
        # [pid 210676] mkdir("/tmp/tmp.tFxEKCJMPB-pipcanary/lib/python3.10/site-packages/tox", 0777) = 0
        package_rule = re.compile(
            r"^\[pid [0-9]+\] mkdir\(\"%s/lib/python.*/site-packages/([a-zA-Z][a-zA-Z0-9_-]+)\", 0777\) = 0"
            % re.escape(tmpdir)
        )

        env = {
            "REQUIREMENTS_FILE": requirement_file,
            "PIPCANARY_VIRTUAL_ENV": tmpdir,
            **dict(os.environ),
        }

        command = ["sh", INSTALL_SCRIPT]
        process = subprocess.Popen(command, stderr=subprocess.PIPE, text=True, env=env)
        pid = process.pid
        package: Optional[str] = "unknown"

        for line in process.stderr:  # type: ignore
            if m := package_rule.match(line):
                package = m.groups()[0]
                print("Scanning package install: %s..." % package)

            for rule in rules:
                if m := rule.match(line):
                    raise SuspiciousAccessDetected(
                        pid,
                        "Found access to %s in package %s" % (m.groups()[1], package),
                    )
        process.wait()

        if process.returncode != 0:
            raise

        with open(os.path.join(tmpdir, "packages.json"), "r") as f:
            return json.load(f)


def get_latest_upload_time(package_name: str, version: str) -> Optional[datetime]:
    try:
        response = requests.get(f"https://pypi.org/pypi/{package_name}/json")
        if response.status_code == 404:
            return None

        data = response.json()
        releases = data.get("releases", {})
        if not releases:
            return None

        uploads = releases.get(version)
        if not uploads:
            return None 

        return max(
            [datetime.fromisoformat(upload["upload_time"]) for upload in uploads]
        )
    except Exception as e:
        raise HTTPError(f"Error fetching release date for {package_name}: {e}")


def check_package_uploads(packages: List[Dict[str, Any]]):
    print("Checking most recent package upload dates...")
    recent_packages = []
    for package in packages:
        name = package["name"]
        version = package["version"]
        upload_time = get_latest_upload_time(name, version)
        if not upload_time:
            print(f"No upload date was found for package {name} on pypi")
            continue

        if upload_time > (datetime.now() - timedelta(days=3)):
            print(
                f"Package {name} {version} was updated too recently: {upload_time}. It's safer to use an older version."
            )
            recent_packages.append(name)

    if recent_packages:
        raise UploadVerificationFailedError(
            "The following packages where uploaded too recently: %s"
            % (",".join(recent_packages))
        )


def pipcanary():
    args = parser.parse_args()
    requirement_file = args.requirement

    try:
        if not requirement_file:
            requirement_file = os.path.join(os.path.curdir, "requirements.txt")

        if not os.path.exists(requirement_file):
            raise InvalidArgumentError(
                "Requirements file %s does not exist" % requirement_file
            )

        packages = scan_packages(requirement_file)
        check_package_uploads(packages)
        print("All packages seem to appear safe!")
    except InvalidArgumentError as e:
        print(str(e))
        exit(1)
    except ScanFailedError as e:
        print(str(e))
        exit(2)
    except SuspiciousAccessDetected as e:
        os.kill(e.pid, signal.SIGKILL)
        print(str(e))
        exit(-1)
    except UploadVerificationFailedError as e:
        print(str(e))
        exit(3)


if __name__ == "__main__":
    pipcanary()
