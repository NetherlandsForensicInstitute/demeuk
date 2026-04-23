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

- Python 3.10 is required, Python 3.14 is recommended.
- Ubuntu is the only OS on which demeuk has been tested.

Installing
----------

PDM
~~~
The recommended way is to install demeuk using `PDM`_. ::

    # Initialize an empty project
    pdm -n --no-git --python 3.14
    # Install demeuk
    pdm add demeuk
.. _a link: https://pdm-project.org/latest/

Running
-------
You can run demeuk using::

    pdm run demeuk [options]
when inside of the project directory. You can also run from somewhere else:::

    pdm run -p /path/to/demeuk demeuk [options]

Run from source
~~~~~~~~~~~~~~~
If you want to run demeuk from source you can also easily do this with PDM.::

    # Clone the repo
    git clone <link to repository>
    cd demeuk
    # Choose a Python interpreter to use (optional)
    pdm use
    # Install dependencies
    pdm install
Upgrading
---------

Upgrading demeuk is quite simple. In case you have installed demeuk through PDM, run::

    pdm update
and you're done!
