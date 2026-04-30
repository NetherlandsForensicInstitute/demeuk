import importlib.util
import inspect
import os


# Discover modules in demeuk/modules
# TODO discover at custom location maybe? Check if this is possible
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

    for file in os.listdir(modules_dir):
        # Look for non-hidden python scripts
        if file.endswith('.py') and not file.startswith('_'):
            # Truncate file extension
            module_name = 'demeuk.modules.' + file[:-3]
            members = inspect.getmembers(importlib.import_module(module_name))
            for name, obj in members:
                if inspect.isclass(obj) and name not in blacklist:
                    # We can exclude a module from registration by setting its parser group to 'exclude'
                    if obj.get_parser_group() != 'exclude':
                        classes |= {obj}

    return classes
