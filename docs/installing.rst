Installing
==========

Install locally
~~~~~~~~~~~~~~~

1. Prerequisites

-  Install `bubblewrap <https://github.com/containers/bubblewrap>`_ (sandboxing tool)

-  Install `strace <https://strace.io>`_ (file access tracking) 

-  activated Python virtual environment such as
   `miniconda <https://docs.conda.io/en/latest/miniconda.html>`__ or
   `virtualenv <https://virtualenv.pypa.io/en/latest/>`__,
   Python Version 3.10 or higher.

2. Install PipCanary

.. code:: sh

   pip install pipcanary

3. Test installation

.. code:: sh

   pipcanary --help


Install in Container
~~~~~~~~~~~~~~~~~~~~

1. Prerequisites

-  `Docker <https://www.docker.com/>`__ from your Linux distribution or
   Docker Desktop.

see: https://github.com/sebastian-kuebeck/pipcanary/tree/main/examples/ci-cd/

3. Build container

.. code:: sh

	docker build -t pipcanary-cicd .

Test installation
^^^^^^^^^^^^^^^^^

1. Create shared directory and sample requirements file

.. code:: sh

   mkdir -p shared

   cat << END > shared/requirements.txt
    Werkzeug<=3.1.7
    click<=8.3.1
    flask
    pip==26.1
   END


2. Run container

.. code:: sh

   docker run --privileged -v "$(PWD)/shared:/var/shared" pipcanary-cicd

From Source
~~~~~~~~~~~

1. Prerequisites

-  `Docker <https://www.docker.com/>`__ from your Linux distribution or
   Docker Desktop.
-  `git <https://git-scm.com/>`__ distributed version control system
-  `Python <https://www.python.org/>`__ Version >= 3.10
-  activated Python virtual environment such as
   `miniconda <https://docs.conda.io/en/latest/miniconda.html>`__ or
   `virtualenv <https://virtualenv.pypa.io/en/latest/>`__


2. Download

.. code:: sh

      git clone https://github.com/sebastian-kuebeck/pipcanary
      cd pipcanary
      pip install -r requirements-dev-locked.txt

3. Test (optional)

Run unit tests:

.. code:: sh

   make test

4. Build wheel

.. code:: sh

   make dist

If all goes well, the pipcanary `wheel
file <https://packaging.python.org/en/latest/tutorials/installing-packages/#source-distributions-vs-wheels>`__
will be in the ``dist`` directory.

It’s named ``dist/pipcanary-<version>-py3-none-any.whl``

5. Install wheel

.. code:: sh

   pip install dist/pipcanary-<version>-py3-none-any.whl