import importlib.util
import inspect
import os

# Use this as a key to sort the arguments alphabetically.
def class_name(cls):
    return cls.__name__

# Discover modules in demeuk/modules
# TODO discover at custom location maybe? Check if this is possible
# TODO look at pathlib for this
def discover_modules():
    project_dir = os.path.dirname(__file__)
    modules_dir = project_dir + '/modules/'


    classes = set()

    # Hardcoded list of classes not to register.
    blacklist = ['ABC', 'Enum', # Python
                 'HelpInfo', 'HelpInfoParam', 'PipelinePosition', 'Result', 'Actions', # Auxiliary objects
                 'Module', 'ParamModule', 'ConfigModule', # Base modules
                 'CheckModule', 'AddModule', 'ModifyModule', 'MacroModule', # Module types
                 'WhitespaceTokenizer', # Not sure why this one is included...
                 ]

    # Recursively look through subdirectories of /modules
    for path, names, files in os.walk(modules_dir):
        for file in files:
            # Look for non-hidden python scripts
            if file.endswith('.py') and not file.startswith('_'):
                relative_path = os.path.relpath(os.path.join(path, file), modules_dir)
                # Truncate file extension
                module_name = 'demeuk.modules.' + relative_path[:-3].replace('/', '.')
                members = inspect.getmembers(importlib.import_module(module_name))
                for name, obj in members:
                    if inspect.isclass(obj) and name not in blacklist:
                        classes |= {obj}

    # TODO Do we want a custom sorting order?
    return sorted(classes, key=class_name)
