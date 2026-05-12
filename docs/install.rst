Install
=======
This document describes how to install demeuk.

Requirements
------------

- Python 3.12 is required, Python 3.14 is recommended.
- Ubuntu is the only OS on which demeuk has been tested.

Installing
----------
The recommended way is to install demeuk using `pipx`_. ::

    pipx install demeuk --python /usr/bin/python3.14

This will make demeuk available everywhere by simply running ``demeuk``.

.. _pipx: github.com/bulletmark/pipxu/

Running
-------
You can run demeuk using::

    demeuk [options]

Development
~~~~~~~~~~~~~~~
If you want to run demeuk from source you can also easily do this with pipx.::

    # Clone the repo
    git clone <link to repository>
    cd demeuk
    # Install from source
    pipx install ./ --python /usr/bin/python3.14

Upgrading
---------

Upgrading demeuk is quite simple. In case you have installed demeuk through PDM, run::

    pipx upgrade demeuk

and you're done!
