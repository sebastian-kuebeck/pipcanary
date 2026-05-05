# PipCanary

[![PyPI version](https://img.shields.io/pypi/v/pipcanary.svg)](https://pypi.org/project/pipcanary/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/pypi/pyversions/pipcanary.svg)](https://pypi.python.org/pypi/pipcanary.svg)

**Supply Chain Attack Prevention Tool for Python Packages**

PipCanary helps protect your Python projects from supply chain attacks by:

- Detecting suspicious filesystem behavior in package installation (e.g., access to SSH keys, sensitive directories, etc.)
- Checking for known vulnerabilities in packages
- Enforcing a **cool-down period** on newly uploaded package versions, giving security researchers and scanners time to identify malicious releases

It acts as a safety layer on top of your existing dependency management workflow.

## Features

- **Behavioral analysis** during package installation and loading using `strace` and `bubblewrap` sandboxing

- **Known vulnerability checks** warns about known vulnerabilities

- **Upload time checks** warns about packages released too recently (default: 7 days)

## Design Goals

- **Simple, focused design**. Following UNIX philosophy, PipCanary aims to assist in protecting against supply chain attacks and that's it.  

- **Minimize False Positives as much as possible**. The goal is to find clear indicators for security problems and no advice for manual inspection. That's the conceptual difference between a *canary* and a *source code scanner*.

- **No additional liability**. It should integrate with existing tooling without causing unnecessary impediments.

## Maturity

This project is in **early development**. While it already provides meaningful protection, expect occasional rough edges. However, it's more secure than using plain `pip`, `poetry`, or `uv` without additional safeguards.

## Requirements

- Linux 
- [Python](https://www.python.org/) 3.10 or higher
- [bubblewrap](https://github.com/containers/bubblewrap) (sandboxing tool)
- [strace](https://strace.io) (file access tracking)
- [pip](https://pip.pypa.io/en/stable/getting-started/)


### Installing dependencies on Ubuntu/Debian

```bash
sudo apt update
sudo apt install bubblewrap strace
```

## Installation

```bash
pip install pipcanary
```

## Usage

### Basic Check

Scan a `requirements.txt` for potential supply chain risks:

```bash
pipcanary -r requirements.txt
```

without argument, it checks the `pyproject.toml` or `requirements.txt` in the current directory.


```bash
pipcanary
```

### Example Outputs

#### All packages look safe:

```text
...
All packages appear to be safe!
```

#### Suspicious behavior detected:

```text
...
Found suspicious access to /home/sebastian/.ssh in package evilpack.

Description: SSH private key exfiltration.
Explanation: The package might be trying to steal your Secure Shell private keys.

This could be dangerous!!!
Don't install this package under any circumstances until you know for sure that this is a false positive!
In doubt, contact the package maintainers!
```

Not that PipCanary immediately kills the scanning process once it detects suspicious behavior to
prevent damage!

#### Known vulnerabilities detected:

```text
...
Auditing 9 packages...
Package Flask:3.1.2 has known vulnerabilities: GHSA-68rp-wp8r-4726 (fixed in 3.1.3).
Package Pygments:1.1 has known vulnerabilities: PYSEC-2021-141 (fixed in 2.7.4), GHSA-pq64-v7f5-gqh8 (fixed in 2.7.4), PYSEC-2023-117 (fixed in 2.15.1), GHSA-mrwq-x4v8-fh7p (fixed in 2.15.0), GHSA-5239-wwwm-4pmq (fixed in 2.20.0).
Summary:
  - Vulnerabilities in the following package(s) were found: Flask:3.1.2, Pygments:1.1.
```

#### Recently uploaded packages (cool-down warning):

```text
...
Auditing 3 packages...
Package MarkupSafe 3.0.3 was updated too recently: 2025-09-27T18:37:40.
  - Consider MarkupSafe<=2.1.3 which has no known vulnerabilities
  - If you are certain that the latest upload is secure, add the following argument: --allow-upload-time='MarkupSafe<=2025-09-27T18:37:40'
Package Werkzeug 3.1.8 was updated too recently: 2026-04-02T18:49:14.
  - The next suitable release Werkzeug: 2.3.6 has known vulnerabilities though: GHSA-hrfv-mqp8-q5rw (fixed in 3.0.1, 2.3.8), PYSEC-2023-221 (fixed in 2.3.8, 3.0.1), GHSA-2g68-c3qc-8985 (fixed in 3.0.3), GHSA-f9vj-2wh5-fj8j (fixed in 3.0.6), GHSA-q34m-jh98-gwm2 (fixed in 3.0.6), GHSA-hgf8-39gv-g3f2 (fixed in 3.1.4), GHSA-87hc-h4r5-73f7 (fixed in 3.1.5), GHSA-29vq-49wr-vm6x (fixed in 3.1.6)
  - If you are certain that the latest upload is secure, add the following argument: --allow-upload-time='Werkzeug<=2026-04-02T18:49:14'
Summary:
  - The following package(s) were uploaded too recently: MarkupSafe, Werkzeug.
```

### Advanced Usage

```text
usage: pipcanary [-h] [--version] [-r REQUIREMENT] [-p PROJECT] [--max-upload-time MAX_UPLOAD_TIME]
                 [-c COOL_DOWN_PHASE_DAYS] [-a ALLOW_UPLOAD_TIME] [-d ADDITIONAL_DIRECTORY] [-t TRACE_FILE]
                 [--sandbox | --no-sandbox] [--do-not-scan DO_NOT_SCAN] [-i INDEX_URL]
                 [--extra-index-url EXTRA_INDEX_URL] [--ignore-vuln IGNORE_VULN] [--log-level LOG_LEVEL]
                 [--temporary-directory TEMPORARY_DIRECTORY] [-l LOCKED_REQUIREMENT]

PipCanary 0.0.11 detects supply chain attacks and known vulnerabilities in python dependencies

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -r, --requirement REQUIREMENT
                        The requirements file, usually requirements.txt.
  -p, --project PROJECT
                        The project file in TOML format. Usually pyproject.toml. If neither -p or -r are set,
                        ./pyproject.toml or if not exists ./requirements.txt is scanned.
  --max-upload-time MAX_UPLOAD_TIME
                        Maximum upload time for all packages (ISO 8601 date and time format). Example: --max-upload-
                        time='2026-04-07T07:43:51+0000'
  -c, --cool-down-phase-days COOL_DOWN_PHASE_DAYS
                        Cool-down phase for packages in days for new package uploads. Default: 7
  -a, --allow-upload-time ALLOW_UPLOAD_TIME
                        Maximum upload time for a single package (ISO 8601 date and time format). Example: --allow-
                        upload-time='requests<=2026-04-07T07:43:51+0000
  -d, --additional-directory ADDITIONAL_DIRECTORY
                        Additional directory mapped into the sandbox while scanningMake sure this directory does not
                        contain sensitive information!
  -t, --trace-file TRACE_FILE
                        The trace file for further analysis
  --sandbox, --no-sandbox
                        Run with sandbox (default). No sandbox might be safe if you are already running within a
                        sandbox!
  --do-not-scan DO_NOT_SCAN
                        Add packages that should not be scanned
  -i, --index-url INDEX_URL
                        URL to PyPi compatible repository
  --extra-index-url EXTRA_INDEX_URL
                        Extra URL to PyPi compatible repository
  --ignore-vuln IGNORE_VULN
                        Ignore the given vulnerability
  --log-level LOG_LEVEL
                        The log level. Supported levels are: FATAL, ERROR, WARNING, INFO, DEBUG
  --temporary-directory TEMPORARY_DIRECTORY
                        Temporary directory. Default: /tmp
  -l, --locked-requirement LOCKED_REQUIREMENT
                        generates a "locked" file with all requirements, the scanned version with hashes
```

## Exit Codes

PipCanary Exit Codes, description and recommended actions.

| Exit Code | Description                            | Recommended Action                   |
| --------- | ---------------------------------------| ------------------------------------ |
|       -1  | Preconditions to run this tool failed. Examples: Missing bubblewrap, strace.  | Fix precondition and rerun PipCanary. |
|        0  | Scan and subsequent Audit completed successfully. | It is safe to continue. |                               
|        1  | Invalid argument value. | Fix arguments and rerun PipCanary. |
|        2  | Scanning process crashed. | Check error message for details. |
|        3  | Failed to download package Information from Index.  | Fix connection to index and rerun PipCanary. |
|        4  | Known vulnerability or too recent upload detected.  | Change requirements and/or PipCanary arguments and rerun PipCanary |
|        5  | Malicious activity detected during scan. | Hard Block & Quarantine: Immediately terminate the build. Delete the build workspace and alert the Incident Response (IR) team for a potential supply-chain attack.|


## Security Model

PipCanary does the following:

- It installs packages in a sandboxed environment (using bubblewrap) and tries to load all installed packages inside the sandboxed environment.

- It scans the activities inside the sandboed environment for potentially malicious file system access (using strace).

- If it detects potentially malicious file system access, it kills all processes in the sandboxed environment and reports its findings.

- All packages get removed immediately after scanning.

- After scanning, it consults the [PyPI JSON API](https://docs.pypi.org/api/json/) for known vulnerabilities of all installed packages and reports its findings.

**Note that all of the precautions offer better security than running `pip install` alone "unprotected" but they do not guarantee absolute security for the packages being scanned or the scanning process itself**!

### Examples:

- The sandboxed environment has network access to the host machine during the installation process,
  so it is **not advised to run it inside a network with access to sensitive systems or components**!

- If a malicious packages postpones it's malicious activities after module loading, PipCanary has no chance of detecting this! **PipCanary does not contain a static source code scanner**!

### Conclusion

There are natural limitations to all checks PipCanary performs so **running PipCanary is no guarantee for perfect security**. As such PipCanary (as well as any other security tool) can only be a **part of a wider security strategy**!

## Similar Projects

- [pip-audit](https://github.com/pypa/pip-audit)
- [guarddog](https://github.com/DataDog/guarddog)
- [pip-tools](https://pypi.org/project/pip-tools/)

## Further Information on PyPi Suppy Chain Attacks

- [OWASP Top 10 2025: A03 Software Supply Chain Failures](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/)
- [OWASP Top 10 2025: A08 Software or Data Integrity Failures](https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/)

