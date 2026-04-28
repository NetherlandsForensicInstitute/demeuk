import sys
from argparse import ArgumentParser

from .config import Config
from .modules.base import EmailCheckModule, EndingWithCheckModule, ParamModule
from .parser2 import Parser
from .pipeline import Pipeline


def main():
    all_modules = [EmailCheckModule, EndingWithCheckModule]

    # Create parser class (create wrapper around argparse.ArgumentParser)
    parser = Parser("5.0.0")


    for module in all_modules:
        parser.register(module)

    # Argparse validates arguments
    parser.parse_args()

    cfg = Config(parser.args)

    # Global config can be done here (in/out file, log etc.)

    pipeline = Pipeline(parser, sys.argv)
    print(parser.lookup_table)
    for module in pipeline.modules:
        if isinstance(module, ParamModule):
            print(str(module) + ' with param ' + module.param)
        else:
            print(module)
