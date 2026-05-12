Adding new modules to demeuk
============================
Demeuk contains a lot of modules already, but if you want to add your own custom module these are
some things to keep in mind:

General ideas
-------------
To implement a custom module, create a Python file in ``src/demeuk/modules`` and create a class
which inherits from either CheckModule, ModifyModule, AddModule, RemoveModule or MacroModule
depending on the desired functionality. Additionally this class may inherit from ParamModule, for
supplying a command-line parameter to the module, or ConfigModule if it depends on some other
configuration.

Properties of the module, as well as its workings are configured by implementing a set of abstract
methods.

Modules are automatically discovered and registered to the argument parser at runtime, so
implementing a module can take place entirely within a single file.

Help info
---------
The help info of a module describes how you can invoke it from the command-line, and it contains
what to display when ``demeuk -h`` is run. To set the help info, implement ``get_help_info()``
to return a ``HelpInfo`` object, which is a named tuple containing the fields:

* option, which is either a string or a list of strings of command-line options. If a list is supplied, all of these will be added as aliases.
* help_str, which is a string containing a short description on how the module functions.

If your module takes a parameter, it implements ParamModule in which case ``get_help_info()`` must
return a ``HelpInfoParam`` object. This is a named tuple containing the same info as above, in
addition to:

* param_type, which is the Python type of the parameter (for example int, str).
* metavar, a name by which the parameter can be referenced by help_str, for example '<str>' or '<amt>'

The run function
----------------
The main functionality of the module will be implemented in ``run()``. This function takes one line
as input, and outputs a ``Result`` tuple. How to configure the return result depends on the type of module.

Adding a check module
^^^^^^^^^^^^^^^^^^^^^
A check module (or more precisely, a class which implements ``CheckModule``) chooses whether to
continue running the module pipeline on the current line, or drop a line and continue to the next.
For these results, ``CheckModule`` supplies the shortcuts ``next`` and ``stop`` respectively.

Adding a modify/remove module
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Modify or remove modules can modify an existing line. For performance, we only update the line if it is actually different from the input line.
Therefore, after determining the modified line, we check if it is equal to the original line and only if it differs, we send the update Result.
``ModifyModule`` and ``RemoveModule`` provides the shortcut ``get_result(line, cleaned_line)``.

Adding an add module
^^^^^^^^^^^^^^^^^^^^
Add modules add variants of a line to the work queue. Most add module only add a single variant,
and we want to only add it if it differs from the original line, just as with the modify and remove modules.
Therefore ``AddModule`` supplies ``get_result(line, added_line)``.


Accessing a parameter
^^^^^^^^^^^^^^^^^^^^^
Some modules depend on a user-specified parameter, for example a check module which drops lines if their length is over a certain number of characters.
For this, you can implement ``ParamModule`` (in addition to one of the four above module types).
For ParamModule implementations, you need to return a ``HelpInfoParam`` from ``get_help_info()``,
and you can access the parameter inside ``run()`` with ``self.param``.



Advanced modules
----------------
Demeuk modules are very customizable; you can override the standard 'control flow handlers' to
expose a lot of flexibility.

Position in pipeline
^^^^^^^^^^^^^^^^^^^^
Demeuk runs its input through a pipeline, which is a linear sequence of modules. The action
of a module on types determines its place in the pipeline.

Input is read as bytes, at some point it is *encoded*, at which point these bytes are treated as a
Python string. At this point we can work with the input as strings of characters. Keeping this in
mind, a module can fall in three classes:

* A module which takes bytes as input and returns a byte sequence,
* A module which takes bytes as input and returns a string (an *encoding* module),
* A module which takes a string as input and returns a string.

The position can be set by overriding ``get_pipeline_position()``, which should return either
``PipelinePosition.BEFORE_ENCODE``, ``PipelinePosition.ENCODE`` or ``PipelinePosition.AFTER_ENCODE``
for the first, second and respectively third category.
Most modules simply take in a string and output a string, so they fall in the third category.
This is the default behaviour (what happens when you don't override ``get_pipeline_position()``).

Accessing config
^^^^^^^^^^^^^^^^
If your module depends on a config value which should not be passed as a parameter (for example
because it is already set somewhere else, or you want multiple modules to be able to use the same config),
you can implement ``ConfigModule``. The master object containing all config about the program is
a ``Config`` instance, so the config value must come from here. To 'register' a config value to a module,
run ``add_config(key, value)`` inside of ``set_configs(config)``. You can later retrieve this value with ``get_config(key)``.

Adding a macro module
^^^^^^^^^^^^^^^^^^^^^
You might want to create a module which runs a collection of other modules, and possibly process this result some more.
For this, you need a macro module. When you implement a ``MacroModule``, you can provide a list of module instances
in ``get_submodules()``, which will be inserted in order [#f1]_ into the module pipeline.
Note that this list needs to consist of *instances* of modules, so if you want to include a module
with a parameter of config, you need to supply this in ``get_submodules()``.

By default, ``run()`` simply continues to the next module but you can override this function
if you want the macro module to perform some action. Note that if you override ``run()``, you will
need to construct a Result object, and implement a result handler in ``handle()``, see the next
section on how to do this. Also keep in mind that macro modules are added *after* their submodules in the pipeline.

Customizing the result handler
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
If you want your module to perform actions which do not fall neatly in the described behaviors above
(for example: adding multiple lines to the work queue, change logging behavior, or adding a module
in the queue and stopping further processing), you can return a custom ``Result`` and override the
``handle(result)`` function.

The ``Result`` object returned from ``run()`` contains a ``status`` field which, if set to True,
passes on the ``Result`` to ``handle(result)``. This function will return an ``Actions`` object
which tells the program what actions to take concerning the current line.

``Actions`` is a tuple containing the following values:

* ``stop`` - If True, drop this line completely and go to the next line.
* ``add`` - A list of lines to add to the work queue.
* ``update`` - The string to replace the current line with
* ``do_not_re_encode`` - A flag which, if set to True, adds a line back without re-encoding it as a string.
* ``log_str`` - A string to log to the log file or stderr
* ``debug_str`` - A string to log to the log file or stderr if ``--debug`` is set
* ``debug_add_str`` - A string to log to the log file or stderr if ``--debug`` is set, for adding lines to the queue.

If a value is not set, no action will be taken. So for example, if we want to add a single line
without logging anything we simply return a ``Actions(add=[line])`` from ``handle()``.

Performance considerations
^^^^^^^^^^^^^^^^^^^^^^^^^^
If you plan on running your modules on large lists, note that the module's ``run()`` function
is called for every line and this is therefore the place you should look first for optimizations.
Avoid allocating memory or instantiating large objects here, and instead prefer to pre-allocate or
store results if you can.

.. rubric:: Footnotes

.. [#f1] That is, relative ordering of the modules which share a pipeline position is preserved. If you return a list of modules with ``PipelinePosition.AFTER_ENCODE`` and you append a module with ``PipelinePosition.BEFORE_ENCODE``, the final module will be added before the rest.