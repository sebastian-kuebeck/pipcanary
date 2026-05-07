==========
PipCanary
==========

**Supply Chain Attack Prevention Tool for Python Packages**

PipCanary helps protect your Python projects from supply chain attacks by:

* Detecting suspicious filesystem behavior in package installation (e.g., access to SSH keys, sensitive directories, etc.)
* Checking for known vulnerabilities in packages
* Enforcing a **cool-down period** on newly uploaded package versions, giving security researchers and scanners time to identify malicious releases

It acts as a safety layer on top of your existing dependency management workflow.

Features
========

* **Behavioral analysis** during package installation and loading using ``strace`` and ``bubblewrap`` sandboxing
* **Known vulnerability checks** warns about known vulnerabilities
* **Upload time checks** warns about packages released too recently (default: 7 days)

Design Goals
============

* **Simple, focused design**. Following UNIX philosophy, PipCanary aims to assist in protecting against supply chain attacks and that's it.
* **Minimize False Positives as much as possible**. The goal is to find clear indicators for security problems and no advice for manual inspection. That's the conceptual difference between a *canary* and a *source code scanner*.
* **No additional liability**. It should integrate with existing tooling without causing unnecessary impediments.

Maturity
========

This project is in **early development**. While it already provides meaningful protection, expect occasional rough edges. However, it's more secure than using plain ``pip``, ``poetry``, or ``uv`` without additional safeguards.

Requirements
============

* Linux
* `Python <https://www.python.org/>`_ 3.10 or higher
* `bubblewrap <https://github.com/containers/bubblewrap>`_ (sandboxing tool)
* `strace <https://strace.io>`_ (file access tracking)
* `pip <https://pip.pypa.io/en/stable/getting-started/>`_

Installing dependencies on Ubuntu/Debian
----------------------------------------

.. code-block:: bash

   sudo apt update
   sudo apt install bubblewrap strace

Installation
============

.. code-block:: bash

   pip install pipcanary

Usage
=====

Basic Check
-----------

Scan a ``requirements.txt`` for potential supply chain risks:

.. code-block:: bash

   pipcanary -r requirements.txt

without argument, it checks the ``pyproject.toml`` or ``requirements.txt`` in the current directory.

.. code-block:: bash

   pipcanary -p pyproject.toml

Example Outputs
---------------

All packages look safe:
^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: text

   ...
   All packages appear to be safe!

Suspicious behavior detected:
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: text

   ...
   Found suspicious access to /home/sebastian/.ssh in package evilpack.

   Description: SSH private key exfiltration.
   Explanation: The package might be trying to steal your Secure Shell private keys.

   This could be dangerous!!!
   Don't install this package under any circumstances until you know for sure that this is a false positive!
   In doubt, contact the package maintainers!

Note that PipCanary immediately kills the scanning process once it detects suspicious behavior to prevent damage!

Known vulnerabilities detected:
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: text

   ...
   Auditing 9 packages...
   Package Flask:3.1.2 has known vulnerabilities: GHSA-68rp-wp8r-4726 (fixed in 3.1.3).
   Package Pygments:1.1 has known vulnerabilities: PYSEC-2021-141 (fixed in 2.7.4), GHSA-pq64-v7f5-gqh8 (fixed in 2.7.4), PYSEC-2023-117 (fixed in 2.15.1), GHSA-mrwq-x4v8-fh7p (fixed in 2.15.0), GHSA-5239-wwwm-4pmq (fixed in 2.20.0).
   Summary:
     - Vulnerabilities in the following package(s) were found: Flask:3.1.2, Pygments:1.1.

Recently uploaded packages (cool-down warning):
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: text

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

Security Model
==============

PipCanary does the following:

* It installs packages in a sandboxed environment (using bubblewrap) and tries to load all installed packages inside the sandboxed environment.
* It scans the activities inside the sandboed environment for potentially malicious file system access (using strace).
* If it detects potentially malicious file system access, it kills all processes in the sandboxed environment and reports its findings.
* All packages get removed immediately after scanning.
* After scanning, it consults the `PyPI JSON API <https://docs.pypi.org/api/json/>`_ for known vulnerabilities of all installed packages and reports its findings.

**Note that all of the precautions offer better security than running pip install alone "unprotected" but they do not guarantee absolute security for the packages being scanned or the scanning process itself**!

Examples
--------

* The sandboxed environment has network access to the host machine during the installation process, so it is **not advised to run it inside a network with access to sensitive systems or components**!
* If a malicious packages postpones it's malicious activities after module loading, PipCanary has no chance of detecting this! **PipCanary does not contain a static source code scanner**!

Conclusion
----------

There are natural limitations to all checks PipCanary performs so **running PipCanary is no guarantee for perfect security**. As such PipCanary (as well as any other security tool) can only be a **part of a wider security strategy**!


Narrative Documentation
=======================
.. toctree::
   :maxdepth: 2

   how_it_works.rst
   installing.rst
   usage.rst
   exit_codes.rst

Indices and Tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

Similar Projects
================

* `pip-audit <https://github.com/pypa/pip-audit>`_
* `guarddog <https://github.com/DataDog/guarddog>`_
* `pip-tools <https://pypi.org/project/pip-tools/>`_

Further Information on PyPi Suppy Chain Attacks
===============================================

OWASP Top 10 2025
-----------------

* `OWASP Top 10 2025: A03 Software Supply Chain Failures <https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/>`_
* `OWASP Top 10 2025: A08 Software or Data Integrity Failures <https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/>`_

Incidents
---------

* `PyTorch Lightning and Intercom-client Hit in Supply Chain Attacks to Steal Credentials <https://thehackernews.com/2026/04/pytorch-lightning-compromised-in-pypi.html>`_
* `Incident Report: LiteLLM/Telnyx supply-chain attacks, with guidance <https://blog.pypi.org/posts/2026-04-02-incident-report-litellm-telnyx-supply-chain-attack/>`_
