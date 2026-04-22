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
Package pip:25.0.1 has known vulnerabilities: ECHO-ffe1-1d3c-d9bc, ECHO-7db2-03aa-5591, GHSA-6vgw-5pg2-w6jp, GHSA-4xh5-x5gv-qwph.

Vulnerabilities in the following package(s) were found: pip:25.0.1.
```

#### Recently uploaded packages (cool-down warning):

```text
...
Package click 8.3.2 was updated too recently: 2026-04-03T19:14:45.
It might be safer to use an older version.
Consider click<=8.3.1 or earlier and check for known vulnerabilities.

If you are certain that the latest version is safe, you can allow it with:

    --allow-upload-time='click<=2026-04-03T19:14:45'
```

### Advanced Usage

```text
usage: PipCanary [-h] [-r REQUIREMENT] [-p PROJECT] [--max-upload-time MAX_UPLOAD_TIME] [-c COOL_DOWN_PHASE_DAYS] [-a ALLOW_UPLOAD_TIME]
                 [-d ADDITIONAL_DIRECTORY] [-t TRACE_FILE] [--sandbox | --no-sandbox] [--do-not-scan DO_NOT_SCAN] [-i INDEX_URL]
                 [--extra-index-url EXTRA_INDEX_URL] [--ignore-vuln IGNORE_VULN]

Detects supply chain attacks in python dependencies

options:
  -h, --help            show this help message and exit
  -r REQUIREMENT, --requirement REQUIREMENT
                        The requirements file, usually requirements.txt.
  -p PROJECT, --project PROJECT
                        The project file in TOML format. Usually pyproject.toml. If neither -p or -r are set, ./pyproject.toml or if not exists
                        ./requirements.txt is scanned.
  --max-upload-time MAX_UPLOAD_TIME
                        Maximum upload time for all packages (ISO 8601 date and time format). Example: --max-upload-
                        time='2026-04-07T07:43:51+0000'
  -c COOL_DOWN_PHASE_DAYS, --cool-down-phase-days COOL_DOWN_PHASE_DAYS
                        Cool-down phase for packages in days for new package uploads. Default: 7
  -a ALLOW_UPLOAD_TIME, --allow-upload-time ALLOW_UPLOAD_TIME
                        Maximum upload time for a single package (ISO 8601 date and time format). Example: --allow-upload-
                        time='requests<=2026-04-07T07:43:51+0000
  -d ADDITIONAL_DIRECTORY, --additional-directory ADDITIONAL_DIRECTORY
                        Additional directory mapped into the sandbox while scanningMake sure this directory does not contain sensitive
                        information!
  -t TRACE_FILE, --trace-file TRACE_FILE
                        The trace file for further analysis
  --sandbox, --no-sandbox
                        Run with sandbox (default). No sandbox might be safe if you are already running within a sandbox!
  --do-not-scan DO_NOT_SCAN
                        Add packages that should not be scanned
  -i INDEX_URL, --index-url INDEX_URL
                        URL to PyPi compatible repository
  --extra-index-url EXTRA_INDEX_URL
                        Extra URL to PyPi compatible repository
  --ignore-vuln IGNORE_VULN
                        Ignore the given vulnerability
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

## Further Information on PyPi Suppy Chain Attacks

- [OWASP Top 10 2025: A03 Software Supply Chain Failures](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/)
- [OWASP Top 10 2025: A08 Software or Data Integrity Failures](https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/)
- [How a Poisoned Security Scanner Became the Key to Backdooring LiteLLM](https://snyk.io/de/articles/poisoned-security-scanner-backdooring-litellm/)
- [The Team PCP Snowball Effect: A Quantitative Analysis](https://blog.gitguardian.com/team-pcp-snowball-analysis/)
