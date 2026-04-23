Adding new modules to demeuk
============================
Demeuk contains a lot of modules already, but if you want to add your own custom module these are
some things to keep in mind:

Fixed or modular?
-----------------
Demeuk has two modes of executing modules: a *fixed* function pipeline of modules which are executed
in a static order defined in the source code, and a *modular* pipeline where modules are executed
based on the order in which they are passed on the command-line.

The modular pipeline is the place for modules which either:

* Removes a line if some condition is satisfied (Check module)
* Modifies a line, for example fixing encoding mistakes (Modify module)
* Adds new lines, for example splitting a line on a certain delimiter (Add module)
* Removes parts of a line (Remove module)
**and** the module acts on Python strings, meaning it takes in a string and (possibly) outputs a
string.

If you need more specific functionality, for example a module which performs some oepration on the
encoded bytes, or a module which modifies certain lines after which is stops all further processing,
you need a fixed pipeline module.

In general the modular pipeline is preferred, as this needs less code duplication and more
flexibility in how it is used.

.. _modular:
Adding a modular pipeline module
--------------------------------
The modular pipeline functions on some assumptions: The modules take a (decoded) Python string as
input, and possibly one other input argument (which must be specified on the command-line).
All modules return a boolean ``status``, which tells the pipeline if it needs to perform some action
or continue to the next module without doing anything. This should be the first return value.

To add a modular pipeline module, first you need to determine in which of the four categories
(Check, Modify, Add, Remove) the module falls. You also need to decide if the module will take an
additional input (in which case the corresponding command-line option will be called a *parameter*)
or not (in which case the option will be a *flag*).

Adding a check module
^^^^^^^^^^^^^^^^^^^^^
A check module expects a single ``string line`` as input, and it has to provide a tuple of type
``(bool status, string debug_msg)`` as output. If the input line needs to be discarded,
``status`` should be ``True``. If the line is discarded and ``--debug`` is passed to the program,
the debug message will be logged in addition to the input. Example for a check parameter in
pseudocode::

    def check_some_condition(line, arg):
        if some_condition(line) and some_other_condition(line, arg):
            return True, 'Checked some condition'
        return False, None
After you have written the functionality of the module, you tell the argument parser about its
existence in `parser.py`. If the module is a flag, you add an entry to the `flags_check` dict
where the key is your desired command-line option (for example ``--check-some-condition``),
and the value should be a list ``[func, help_string]`` where ``func`` is the function object of your
module, and the help_string is the string which will be displayed when passing ``-h`` to demeuk. To
'register' the above example function::

    flags_check = dict({
        ...
        '--check-some-condition': [check_some_condition, 'Discard lines that satisfy some condition']
    })
TODO: for a parameter this is different.
.. _fixed:
Adding a fixed pipeline module
------------------------------
