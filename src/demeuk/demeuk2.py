import sys
from argparse import ArgumentParser
from os import cpu_count, linesep

from .config import Config

from .modules.base import *
from .modules.encode import *
from .modules.macro import *

from .modules.check import *
from .modules.modify import *
from .modules.add import *
from .modules.remove import *

from .parser2 import Parser
from .pipeline import Pipeline

from .discover import discover_modules



def main():
    all_modules = discover_modules()

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

    cfg.logger.stderr_print(f'Running demeuk - {version}')
    cfg.logger.stderr_print(f'Using {cfg.threads} out of {cpu_count()} available CPUs')
    cfg.logger.stderr_print(f'Chunking file {cfg.input_file}...')


    # Read whole file (debug), chunk and multiprocess this.
    lines = []
    with open(cfg.input_file, 'rb') as file_handle:
        lines = [line.rstrip(b'\n') for line in file_handle.readlines()]

    cfg.logger.stderr_print('Running pipeline...')

    cfg.logger.write_log(f'Running demeuk - {version}{linesep}')

    results = pipeline.run(lines, cfg)

    cfg.logger.stderr_print('Writing results to file')
    cfg.logger.write_results(results)

    cfg.logger.stderr_print('Done')