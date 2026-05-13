import importlib.util
import inspect
from pathlib import Path

from demeuk.modules.base import Module


"""
Discovers demeuk modules dynamically.
"""

def class_name(cls):
    """Utility function to determine sorting of command-line options"""
    return cls.__name__

def discover_modules():
    """
    Discover demeuk modules in src/demeuk/modules.
    Any class which is a subclass of Module is detected and registered automatically.
    """
    root_dir = Path('.') / 'src' / 'demeuk'
    modules_dir = root_dir / 'modules'

    classes = set()

    # Hardcoded list of classes not to register.
    # This is because Python does not distinguish between concrete and abstract subclasses.
    blacklist = [
                 'Module', 'ParamModule', 'ConfigModule', # Base modules
                 'CheckModule', 'AddModule', 'ModifyModule', 'MacroModule', 'RemoveModule', # Module types
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
                    if inspect.isclass(obj):
                        if issubclass(obj, Module) and name not in blacklist:
                            classes |= {obj}

    return sorted(classes, key=class_name)
