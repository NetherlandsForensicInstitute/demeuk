import sys
from argparse import ArgumentParser

from .config import Config
from .modules.base import EmailCheckModule, EndingWithCheckModule, ParamModule
from .parser2 import Parser
from .pipeline import Pipeline


def main():
    all_modules = [EmailCheckModule, EndingWithCheckModule]

    parser = Parser("5.0.0")


    for module in all_modules:
        parser.register(module)

    # Argparse validates arguments
    parser.parse_args()

    cfg = Config(parser.args)

    # Global config can be done here (in/out file, log etc.)

    pipeline = Pipeline(parser, sys.argv)


    # Read whole file (debug)
    lines = []
    with open(cfg.input_file, 'rb') as file_handle:
        lines = [line.rstrip(b'\n') for line in file_handle.readlines()]

    results = pipeline.run(lines, cfg.logger)

    cfg.logger.write_results(results)