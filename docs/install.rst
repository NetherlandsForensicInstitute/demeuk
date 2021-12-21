Install
=======
This document describes how to install demeuk.

There are multiple ways to install python packages

- System-wide
- User specific
- Virtual environment

The recommended way to install demeuk is to install it in a virtual
environment.

Requirements
------------

- Python 3.6 is required
- Ubuntu 18.04 is the only OS on which demeuk has been tested.

Installing
----------

Virtual environment
~~~~~~~~~~~~~~~~~~~

.. code-block:: none

    $ sudo apt install python3-pip
    $ sudo pip3 install virtualenv
    $ cd <some place where the virtual environment will be created>
    $ virtualenv venv-demeuk
    $ source venv-demeuk/bin/activate

Installing from PyPi
~~~~~~~~~~~~~~~~~~~~

.. code-block:: none

    $ pip3 install demeuk

Installing from source
~~~~~~~~~~~~~~~~~~~~~~
If for some reason the PyPi is not available, you can build the wheelfile
yourself. First create a Virtual environment as described above.
:ref:`Virtual environment`

.. code-block:: none

    $ git clone <link to repository>
    $ cd demeuk
    $ python3 setup.py bdist_wheel
    $ pip3 install dist/*.whl

Run from source
~~~~~~~~~~~~~~~
If for some reason you want to run demeuk from source you only have to install
the requirements.

.. code-block:: none

    $ git clone <link to repository>
    $ cd demeuk
    $ pip3 install -r requirements.txt
    $ python3 bin/demeuk.py --help

Upgrading
---------

Upgrading demeuk is quite simple. In case you have installed demeuk through pip
and using a virtualenv:

.. code-block:: none

    $ source venv-demeuk/bin/activate
    $ pip3 install demeuk --upgrade

In case that you installed demeuk using the source, just rebuild the software
and install the wheel file. Pip3 will upgrade the package automatically. 
