import sys
from argparse import ArgumentParser

from .config import Config
from .modules.base import *
from .modules.encode import *
from .parser2 import Parser
from .pipeline import Pipeline


def main():
    # TODO: autodiscover modules.
    all_modules = [EmailCheckModule, EndingWithCheckModule, FirstUpperAddModule, CleanTrimModifyModule,
                   TransliterateModifyModule, HexModule, EncodeModule]

    version = '5.0.0'

    parser = Parser(version)


    for module in all_modules:
        parser.register(module)

    # Argparse validates arguments
    parser.parse_args()

    cfg = Config(parser.args)

    # Global config can be done here (in/out file, log etc.)

    pipeline = Pipeline(parser, sys.argv, cfg)

    print(pipeline.modules)

    cfg.logger.stderr_print(f'Main: running demeuk - {version}')

    # Read whole file (debug)
    lines = []
    with open(cfg.input_file, 'rb') as file_handle:
        lines = [line.rstrip(b'\n') for line in file_handle.readlines()]

    results = pipeline.run(lines, cfg)

    cfg.logger.write_results(results)