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

.. _pipx: https://pipx.pypa.io/stable/

Running
-------
You can run demeuk using::

    demeuk [options]

Development
~~~~~~~~~~~~~~~
If you want to run demeuk from source you can also easily do this with pipx: ::

    # Clone the repo
    git clone <link to repository>
    cd demeuk
    # Install from source
    pipx install ./ --python /usr/bin/python3.14

If you change the Python source, you will have to run::

    pipx upgrade demeuk

to reload the shortcut ``demeuk``.

Alternatively, you can use PDM: ::

    # Clone the repo
    git clone <link to repository>
    cd demeuk
    # Set up PDM project
    pdm init -n --no-git --python /usr/bin/python3.14

in which case you don't have to reload the command everytime you change the source code, but you then have to run demeuk with ::

    pdm run demeuk [options]

which is also not globally available.
