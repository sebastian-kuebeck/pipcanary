Usage
=====

Scan all Packages in a requirements or project file 
---------------------------------------------------

Scan a ``requirements.txt`` for potential supply chain risks:

.. code-block:: bash

   pipcanary -r requirements.txt -l requirements-locked.txt 

without argument, it checks the ``pyproject.toml`` or ``requirements.txt`` in the current directory.

.. code-block:: bash

   pipcanary -p pyproject.toml -l 

Example response:
^^^^^^^^^^^^^^^^

.. code-block:: text

   ...
   All packages appear to be safe!



Command Line Options
--------------------

.. code-block:: text

   usage: pipcanary [-h] [--version] [-r REQUIREMENT] [-p PROJECT] [--max-upload-time MAX_UPLOAD_TIME]
                    [-c COOL_DOWN_PHASE_DAYS] [-a ALLOW_UPLOAD_TIME] [-d ADDITIONAL_DIRECTORY] [-t TRACE_FILE]
                    [--sandbox | --no-sandbox] [--do-not-scan DO_NOT_SCAN] [-i INDEX_URL]
                    [--extra-index-url EXTRA_INDEX_URL] [--ignore-vuln IGNORE_VULN] [--log-level LOG_LEVEL]
                    [--temporary-directory TEMPORARY_DIRECTORY] [-l LOCKED_REQUIREMENT]


``-h`` or ``-help``
^^^^^^^^^^^^^^^^^^^
Shows help information and exits. No scan is performed.

``-version``
^^^^^^^^^^^^
Shows the PipCanary version. No scan is performed.

``-r`` or ``--requirement`` <requirements file>
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
The requirements file (usually ``requirements.txt``) to be scanned.

Example:

.. code-block:: sh

   pipcanary -r requirements.txt


``-p`` or ``--project`` <project file>
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
The project file in TOML format (usually ``pyproject.toml``) to be scanned.

If neither ``-r`` nor ``-p`` is set, PipCanary will try to scan ``./pyproject.toml`` or if not exists ``./requirements.txt``.

Example:

.. code-block:: sh

   pipcanary -p pyproject.toml


**Not that in the current implementation it only reads dependencies from the list ``dependencies``
in Section ``project``!**

Use ``pip-compile`` from `https://pypi.org/project/pip-tools/`_ for advanced
dependency retrieval mechanisms. This will extract a complete requirements file
that can be used by PipCanary.

``-l``, ``--locked-requirement`` <locked requirement file>
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Generates a "locked" file with all scanned requirements with hashes.

Example:

.. code-block:: sh

   pipcanary -r requirements.txt -l requirements-locked.txt


You can use the locked requirements for the following purposes:

1. Install scanned packages with pip, uv or poetry.

Example:

.. code-block:: sh

   pip install -r requirements-locked.txt

2. Generate an SBOM 

.. code-block:: sh

   cyclonedx-py requirements requirements-locked.txt > requirements-locked.cdx.json

see: `CycloneDX Python SBOM Generation Tool <https://pypi.org/project/cyclonedx-bom/>`_

``-a``, ``--allow-upload-time`` <package name><=<upload time>
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Maximum upload time for a single package (ISO 8601 date and time format).

There are cases where it is better to use a package with fixed vulnerabilities although 
it has been uploaded rather recently - especially if the legitimacy of the package can be checked
with trusted sources. This options lets you an upload time specific to a package.

This option can be set multiple times.

Example:

.. code-block:: sh

   pipcanary -r requirements.txt --allow-upload-time 'requests<=2026-04-07T07:43:51+0000' --allow-upload-time 'werkzeug<=2026-04-07T07:43:51+0000'


``--do-not-scan`` <package name>
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Exclude the given package from scanning. 

In case of a file or URL dependency, you have to specify the whole line in the requirements file to be recognized.

Exclusion of a package is NOT possible if the package is pip (as this is absolutely necessary for scanning)
or a package another package to be scanned depends upon.

**Do this only if you are absolutely sure what you are doing!**

This option can be set multiple times.

Example:

.. code-block:: sh

   pipcanary -r requirements.txt --do-not-scan pygments


``--ignore-vuln`` <vulnerability id>
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Ignore a given vulnerability. The vulnerabitity ID can be A CVE, GHSA or PYSEC ID.
Generally every ID contained in PyPI Metadata is respected.

This is often necessary it a required package has no fixes yet and the vulnerable functionality is not used.

This option can be set multiple times.

Example:

.. code-block:: sh

   pipcanary -r requirements.txt --ignore-vuln GHSA-68rp-wp8r-4726


``-c``, ``--cool-down-phase-days`` <cool down phase in days>
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Cool-down phase for packages in days for new package uploads. Default: 7

Example (extend Cool-down phase to 10 days):

.. code-block:: sh

   pipcanary -r requirements.txt -c 10

``-i``, ``--index-url`` <index url>
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

URL to PyPi compatible repository.
Note that local proxies such as `devpi-server <https://pypi.org/project/devpi-server/>`_ can improve the
scanning performance by orders of magnitude, especially within
slow networks.

Example:

.. code-block:: sh

   pipcanary -r requirements.txt -i http://localhost:3141/root/pypi/+simple/


``--extra-index-url`` <extra index url>
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Extra URL to PyPi compatible repository that is used by pip during the scan.

``-t``, ``--trace-file`` <trace file>
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
The trace file with strace information generated during the scan for further analysis.
See `strace <https://strace.io/>`_ for details of the file contents.

Example:

.. code-block:: sh

   pipcanary -r requirements.txt -t strace-output.txt


``--log-level`` <log level>

Sets log level. Supported levels are: FATAL, ERROR, WARNING, INFO, DEBUG.
The default log level is INFO.

Example:

.. code-block:: sh

   pipcanary -r requirements.txt --log-level DEBUG
