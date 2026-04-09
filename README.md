# PipCanary

**Supply Chain Attack Prevention Tool for Python Packages**

PipCanary helps protect your Python projects from supply chain attacks by:

- Detecting suspicious filesystem behavior in package installation (e.g., access to SSH keys, sensitive directories, etc.)
- Enforcing a **cool-down period** on newly uploaded package versions, giving security researchers and scanners time to identify malicious releases

It acts as a safety layer on top of your existing dependency management workflow.

## Features

- **Behavioral analysis** during package installation using `strace` and `bubblewrap` sandboxing
- **Upload time checks** warns about packages released too recently (default: 7 days)
- Simple CLI integration with `requirements.txt` or other dependency files
- Clear, actionable warnings and recommendations when risks are detected

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
Found suspicious access to /root/.ssh in package evilpack

This could be dangerous!!!
Don't install this package under any circumstances until you know for sure that this is a false positive.
In doubt, contact the package maintainers!
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

## Similar Projects

- [pip-audit](https://github.com/pypa/pip-audit)
- [guarddog](https://github.com/DataDog/guarddog)

## Further Information on PyPi Suppy Chain Attacks

- [How a Poisoned Security Scanner Became the Key to Backdooring LiteLLM](https://snyk.io/de/articles/poisoned-security-scanner-backdooring-litellm/)
- [The Team PCP Snowball Effect: A Quantitative Analysis](https://blog.gitguardian.com/team-pcp-snowball-analysis/)

## License

MIT License
