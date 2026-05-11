import importlib.util
import inspect
from pathlib import Path
import os

# Use this as a key to sort the arguments alphabetically.
def class_name(cls):
    return cls.__name__

# Discover modules in demeuk/modules
def discover_modules():
    root_dir = Path('.') / 'src' / 'demeuk'
    modules_dir = root_dir / 'modules'

    classes = set()

    # Hardcoded list of classes not to register.
    blacklist = ['ABC', 'Enum', # Python
                 'HelpInfo', 'HelpInfoParam', 'PipelinePosition', 'Result', 'Actions', # Auxiliary objects
                 'Module', 'ParamModule', 'ConfigModule', # Base modules
                 'CheckModule', 'AddModule', 'ModifyModule', 'MacroModule', 'RemoveModule', # Module types
                 'WhitespaceTokenizer', # Not sure why this one is included...
                 ]

    # Path.walk is Python 3.12+
    for path, names, files in modules_dir.walk():
        for file in [path/file for file in files]:
            # This way file is a Path object instead of a string.
            if file.suffix == '.py' and file.stem != '__init__':
                module_name = str(file.relative_to(modules_dir))
                # Turn modify/hex.py into .modify.hex
                module_name = '.' + module_name.replace('/', '.').replace('.py', '')
                # Get all python objects in the file
                members = inspect.getmembers(importlib.import_module(module_name, 'demeuk.modules'))
                for name, obj in members:
                    # Save only the class-type objects which are not blacklisted. These should only be the modules.
                    if inspect.isclass(obj) and name not in blacklist:
                        classes |= {obj}

    # TODO Do we want a custom sorting order?
    return sorted(classes, key=class_name)
