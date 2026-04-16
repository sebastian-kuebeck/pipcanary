# PipCanary

**Supply Chain Attack Prevention Tool for Python Packages**

PipCanary helps protect your Python projects from supply chain attacks by:

- Detecting suspicious filesystem behavior in package installation (e.g., access to SSH keys, sensitive directories, etc.)
- Checking for known vulnerabilities in packages
- Enforcing a **cool-down period** on newly uploaded package versions, giving security researchers and scanners time to identify malicious releases

It acts as a safety layer on top of your existing dependency management workflow.

## Features

- **Behavioral analysis** during package installation and loading using `strace` and `bubblewrap` sandboxing
- **Known vulnmerability checks** warns about known vulnerabilities.
- **Upload time checks** warns about packages released too recently (default: 7 days)
- Simple CLI integration with `requirements.txt` or other dependency files
- Clear, actionable warnings and recommendations when risks are detected

## Limitations

There are natural limitations to all checks PipCanary performs so running PipCanary is no gurantee to be secure. As such PipCanary (as well as any other security tool) can only be a part of a wider security strategy!

## Maturity

This project is in **early development**. While it already provides meaningful protection, expect occasional rough edges.

However, it's more secure than using plain `pip`, `poetry`, or `uv` without additional safeguards.

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
pip install pipcanary
```

## Installation

```bash
pipcanary -r requirements.txt
```

## Usage

### Basic Check

Scan a `requirements.txt` for potential supply chain risks:

```bash
pipcanary -r requirements.txt
```

### Example Outputs

#### All packages look safe:

```text
...
All packages appear to be safe!
```

#### Suspicious behaviour detected:

```text
...
Found suspicious access to /home/sebastian/.ssh in package evilpack.

Description: SSH private key exfiltration.
Explanation: The package might be trying to steal your Secure Shell private keys.

This could be dangerous!!!
Don't install this package under any circumstances until you know for sure that this is a false positive!
In doubt, contact the package maintainers!
```
#### Known vulnerabilities:

```text
...
Package click 8.3.2 was updated too recently: 2026-04-03T19:14:45.

Consider click<=8.1.8 which has no known vulnerabilities.

If you are certain that the latest upload is secure, add the following argument...
    --allow-upload-time='click<=2026-04-03T19:14:45'

Package Flask 3.1.3 was updated too recently: 2026-02-19T05:00:57.

The next suitable release Flask: 3.1.0 has known vulnerabilities though: GHSA-4grg-w6v8-c28g, GHSA-68rp-wp8r-4726

If you are certain that the latest upload is secure, add the following argument...
    --allow-upload-time='Flask<=2026-02-19T05:00:57'
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

## Similar Projects

- [pip-audit](https://github.com/pypa/pip-audit)
- [guarddog](https://github.com/DataDog/guarddog)

## Further Information on PyPi Suppy Chain Attacks

- [How a Poisoned Security Scanner Became the Key to Backdooring LiteLLM](https://snyk.io/de/articles/poisoned-security-scanner-backdooring-litellm/)
- [The Team PCP Snowball Effect: A Quantitative Analysis](https://blog.gitguardian.com/team-pcp-snowball-analysis/)

## License

MIT License
