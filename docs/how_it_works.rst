How PipCanary Works
===================

PipCanary scans your requirements- (``requirements.txt``, command line Option ``-r``) 
or project file (``pyproject.toml``, command line Option ``-r``) for malicious dependencies 
and known vulnerabilities.

What it does
^^^^^^^^^^^^

1. It installs packages in a sandboxed environment (using bubblewrap) and tries to load all installed packages inside the sandboxed environment.
2. It scans the activities inside the sandboxed environment for potentially malicious file system access (using strace).
3. If it detects potentially malicious file system access, it kills all processes in the sandboxed environment and reports its findings.
4. All packages get removed immediately after scanning.
5. After scanning, it consults the `PyPI JSON API <https://docs.pypi.org/api/json/>`_ for known vulnerabilities of all installed packages and reports its findings.
6. It uses the same source to check package uploads and warns if it finds packages that have been uploaded during the cool-down period. 

Precautions
^^^^^^^^^^^

No Sandbox is perfectly tight although is as tight as possible as it is implemented.
Moreover, the scanning process needs network access to download packages, so it is not advised to
run PipCanary in a network with access to sensitive components!

As a result, you should use PipCanary on systems without access to sensitive information,
outside of sensitive networks and sites!

Cool-Down Phase
^^^^^^^^^^^^^^^

This makes sure that newly uploaded packages are scanned (by 3rd parties) and can be taken down by PyPi before
being installed on your system. Recent malicious packages got removed within hours, so the (adjustable) cool-down period of 7 days should be sufficient.
This is is an additional safeguard in case the scanner does not detect a malicious package.

Example Outputs
^^^^^^^^^^^^^^^

All packages look safe:
~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: text

   ...
   All packages appear to be safe!

Suspicious behavior detected:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: text

   ...
   Auditing 9 packages...
   Package Flask:3.1.2 has known vulnerabilities: GHSA-68rp-wp8r-4726 (fixed in 3.1.3).
   Package Pygments:1.1 has known vulnerabilities: PYSEC-2021-141 (fixed in 2.7.4), GHSA-pq64-v7f5-gqh8 (fixed in 2.7.4), PYSEC-2023-117 (fixed in 2.15.1), GHSA-mrwq-x4v8-fh7p (fixed in 2.15.0), GHSA-5239-wwwm-4pmq (fixed in 2.20.0).
   Summary:
     - Vulnerabilities in the following package(s) were found: Flask:3.1.2, Pygments:1.1.

Recently uploaded packages (cool-down warning):
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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


Locked requirements file
^^^^^^^^^^^^^^^^^^^^^^^^

It can also create a "locked" requirements file (command line Option ``-l``) after the scan has finished, so you have a 
requirements file with fixed versions and hashes that only contains references to scanned packages.

Example "unlocked" requirements file:

.. code:: 

   virtualenv~=21.2.0
   build~=1.4.0
   black~=26.3.1

Example "locked" requirements file with package hashes:

.. code::

   black==26.3.1 \
      --hash=sha256:86a8b5035fce64f5dcd1b794cf8ec4d31fe458cf6ce3986a30deb434df82a1d2 \
      --hash=sha256:5602bdb96d52d2d0672f24f6ffe5218795736dd34807fd0fd55ccd6bf206168b \
      ...
   build==1.4.2 \
      --hash=sha256:7a4d8651ea877cb2a89458b1b198f2e69f536c95e89129dbf5d448045d60db88 \
      --hash=sha256:35b14e1ee329c186d3f08466003521ed7685ec15ecffc07e68d706090bf161d1
   virtualenv==21.2.0 \
      --hash=sha256:1bd755b504931164a5a496d217c014d098426cddc79363ad66ac78125f9d908f \
      --hash=sha256:1720dc3a62ef5b443092e3f499228599045d7fea4c79199770499df8becf9098