import sys
from math import ceil
from os import cpu_count, linesep, path, access, R_OK
from signal import signal, SIGINT, SIG_IGN

from multiprocess.pool import Pool
from tqdm import tqdm
from .chunk import chunkify, submit, finish_up
from .config import Config

from .parser import Parser
from .pipeline import Pipeline

from .discover import discover_modules

def get_version():
    version = '5.0.0'
    return version


def init_worker():
    signal(SIGINT, SIG_IGN)

def cli_entry_point():

    run_cli(sys.argv)


def run_cli(args):
    all_modules = discover_modules()

    parser = Parser(get_version())


    for module in all_modules:
        parser.register(module)

    # Argparse validates arguments
    parser.parse_args(args)

    cfg = Config(parser.args)

    # Global config can be done here (in/out file, log etc.)

    pipeline = Pipeline(parser, args, cfg)

    cfg.logger.write_log(f'Running pipeline {[module.__class__.__name__ for module in pipeline.modules]}\n')


    cfg.logger.stderr_print(f'Running demeuk - {get_version()}')
    cfg.logger.stderr_print(f'Using {cfg.threads} out of {cpu_count()} available CPUs')


    cfg.logger.write_log(f'Running demeuk - {get_version()}{linesep}')



    if cfg.input_files:
        if cfg.threads > 1:
            demeuk_files(pipeline, cfg.input_files, cfg)
        else:
            demeuk_files_single_threaded(pipeline, cfg.input_files, cfg)
    else:
        demeuk_stdin(pipeline, cfg)

    cfg.logger.close_files()
    cfg.logger.stderr_print('Done')


def demeuk_files(pipeline, input_files, cfg):
    with Pool(cfg.threads, init_worker) as pool:
        cfg.logger.stderr_print(f'Reading input file(s)...')

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
    # This returns the list of results, and the logs.
    return cfg.logger.list_results, cfg.logger.list_log

# For profiling
def demeuk_files_single_threaded(pipeline, input_files, cfg):
    cfg.logger.stderr_print(f'Reading input file(s)...')
    with open(input_files[0], 'rb') as fh:
        lines = [line.rstrip(linesep.encode()) for line in fh.readlines(cfg.chunk_size)]
    cfg.logger.stderr_print('Submitted jobs, waiting for jobs to finish...')

    res = pipeline.run(lines, cfg)
    cfg.logger.write_results(res)
    return cfg.logger.list_results, cfg.logger.list_log

def demeuk_stdin(pipeline, cfg):
    with Pool(cfg.threads, init_worker) as pool:
        cfg.logger.stderr_print(f'Reading from stdin...')

        jobs = []

        chunks = sys.stdin.readlines(cfg.chunk_size)
        while chunks:
            chunk = [line.rstrip('\n').encode(cfg.input_encodings[0]) for line in chunks]
            submit(pool, jobs, pipeline, chunk, cfg)

            chunks = sys.stdin.readlines(cfg.chunk_size)
        cfg.logger.stderr_print('Submitted jobs, waiting for jobs to finish...')

        # Wait for jobs to finish
        finish_up(jobs, cfg)

    return cfg.logger.list_results, cfg.logger.list_log