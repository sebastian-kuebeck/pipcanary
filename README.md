# PipCanary

## Features

- Detects Supply Chain Attacks in Python packages

- Makes sure that new package releases are only installed after a cool down period, so secuity scanners have time to detect vulnerabilities

## Maturity

The project is in early stages. However, it's safer to use this than pip, poetry or uv alone.

## Requirements

- Linux 

- [Python](https://www.python.org/) 3.10 or higher

- [bubblewrap](https://github.com/containers/bubblewrap)

- [strace](https://strace.io)

- [pip](https://pip.pypa.io/en/stable/getting-started/)

## Installation

```bash
    pip install pipcanary
```

## Execution

Check your requirements for potential Supply Chain Attacks

```bash
    pipcanary -r requirements.txt
```

Sample output when all is fine...

```text
    ...
    All packages appear to be safe!    
```

Sample output if a potential attack is detected...

```text
    ...
    Found suspicious access to /root/.ssh in package evilpack

    This could be dangerous!!!
    Don't install this package under any circumstances until you know for sure that this is a false positive!
    In doubt, contact the package maintainers!
```

Sample output when packages were updated during the cooling of phase of one week...

```text
    ...
    Package click 8.3.2 was updated too recently: 2026-04-03T19:14:45. 
    It might be safer to use an older version.
    Consider click<=8.3.1 or earlier and check for potential known vulnerabilities of this version.
    If you are certain that the latest upload is safe, add the following argument...
    --allow-upload-time='click<=2026-04-03T19:14:45'

    Package Werkzeug 3.1.8 was updated too recently: 2026-04-02T18:49:14. 
    It might be safer to use an older version.
    Consider Werkzeug<=3.1.7 or earlier and check for potential known vulnerabilities of this version.
    If you are certain that the latest upload is safe, add the following argument...
    --allow-upload-time='Werkzeug<=2026-04-02T18:49:14'

    The following packages were uploaded too recently: click, Werkzeug
```

## Similar Projects

- [pip-audit](https://github.com/pypa/pip-audit)

## Further Information on PyPi Suppy Chaion Attacks

- [How a Poisoned Security Scanner Became the Key to Backdooring LiteLLM](https://snyk.io/de/articles/poisoned-security-scanner-backdooring-litellm/)
- [The Team PCP Snowball Effect: A Quantitative Analysis](https://blog.gitguardian.com/team-pcp-snowball-analysis/)
