import sys
from math import ceil
from os import cpu_count, linesep, path

from os import name as os_name
if os_name == 'nt':
    from multiprocess.pool import ThreadPool as Pool
else:
    from multiprocess.pool import Pool
from tqdm import tqdm

from .config import Config
from .discover import discover_modules
from .multiproc import chunkify, finish_up, init_worker, submit, write_results
from .parser import CommandLineParser
from .pipeline import Pipeline


"""
Demeuk is a tool to clean up lists of words.
"""

def get_version():
    version = '5.0.0'
    return version


def cli_entry_point():
    """
    Entry point for demeuk, when run from the command-line.
    """
    run_cli(sys.argv)

def run_cli(args):
    """
    Invoke demeuk with command-line arguments

    :param args: A list of command-line arguments, split by space
    :type args: list
    """
    all_modules = discover_modules()

    parser = CommandLineParser(get_version())


    for module in all_modules:
        parser.register(module)

    # Argparse validates arguments
    parser.parse_args(args)

    cfg = Config(parser.args)

    # Global config can be done here (in/out file, log etc.)

    pipeline = Pipeline(parser, args, cfg)

    cfg.logger.write(f'Running demeuk - {get_version()}{linesep}')
    cfg.logger.write(f'Running pipeline {[module.__class__.__name__ for module in pipeline.modules]}\n')

    cfg.logger.stderr_print(f'Running demeuk - {get_version()}')
    cfg.logger.stderr_print(f'Using {cfg.threads} out of {cpu_count()} available CPUs')

    if cfg.input_files is not None:
        if cfg.threads > 1:
            demeuk_files(pipeline, cfg.input_files, cfg)
        else:
            demeuk_files_single_threaded(pipeline, cfg.input_files, cfg)
    else:
        demeuk_stdin(pipeline, cfg)

    cfg.logger.stderr_print('Done')
    cfg.logger.close()
    cfg.output_fh.close()


def demeuk_files(pipeline, input_files, cfg):
    """
    Demeuk a list of input files

    :param pipeline: The module pipeline to run
    :type pipeline: :class:`Pipeline`
    :param input_files: A list of input files
    :type input_files: list
    :param cfg: Configuration
    :type cfg: :class:`Config`
    """
    with Pool(cfg.threads, init_worker) as pool:
        cfg.logger.stderr_print('Reading input file(s)...')

        jobs = []

        for file in tqdm(input_files,
                         desc='Files processed',
                         mininterval=0.5,
                         unit=' files',
                         disable=not cfg.progress,
                         position=0):
            total_chunks = ceil(path.getsize(file) / cfg.chunk_size)
            for chunk in tqdm(chunkify(file, cfg),
                              desc='Chunks processed',
                              mininterval=0.5,
                              unit=' chunks',
                              disable=not cfg.progress,
                              total=total_chunks,
                              position=1):
                submit(pool, jobs, pipeline, chunk, cfg)
        cfg.logger.stderr_print('Submitted jobs, waiting for jobs to finish...')

        # Wait for jobs to finish
        finish_up(jobs, cfg)

# For profiling
def demeuk_files_single_threaded(pipeline, input_files, cfg):
    cfg.logger.stderr_print('Reading input file(s)...')
    with open(input_files[0], 'rb') as fh:
        lines = [line.rstrip(linesep.encode()) for line in fh.readlines(cfg.chunk_size)]
    cfg.logger.stderr_print('Submitted jobs, waiting for jobs to finish...')

    res = pipeline.run(lines, cfg)
    write_results(cfg.output_fh, cfg.logger, res)

def demeuk_stdin(pipeline, cfg):
    """
    Demeuk input from stdin

    :param pipeline: The module pipeline to run
    :type pipeline: :class:`Pipeline`
    :param cfg: Config object
    :type cfg: :class:`Config`
    """
    with Pool(cfg.threads, init_worker) as pool:
        cfg.logger.stderr_print('Reading from stdin...')

        jobs = []

        chunks = sys.stdin.readlines(cfg.chunk_size)
        while chunks:
            chunk = [line.rstrip('\n').encode(cfg.input_encodings[0]) for line in chunks]
            submit(pool, jobs, pipeline, chunk, cfg)

            chunks = sys.stdin.readlines(cfg.chunk_size)
        cfg.logger.stderr_print('Submitted jobs, waiting for jobs to finish...')

        # Wait for jobs to finish
        finish_up(jobs, cfg)