import sys
from math import ceil
from os import cpu_count, linesep, path, access, R_OK
from signal import signal, SIGINT, SIG_IGN

from multiprocess.pool import Pool
from tqdm import tqdm
from .chunk import chunkify, submit, finish_up
from .config import Config

from .parser2 import Parser
from .pipeline import Pipeline

from .discover import discover_modules


def init_worker():
    signal(SIGINT, SIG_IGN)

def main():
    # We should read input here, chunk where?

    results, logs = _main(sys.argv)

    # We should write the files here.

def _main(args):
    all_modules = discover_modules()

    version = '5.0.0'

    parser = Parser(version)


    for module in all_modules:
        parser.register(module)

    # Argparse validates arguments
    parser.parse_args(args)

    cfg = Config(parser.args)

    # Global config can be done here (in/out file, log etc.)

    pipeline = Pipeline(parser, args, cfg)

    cfg.logger.write_log(f'Running pipeline {[module.__class__.__name__ for module in pipeline.modules]}\n')


    cfg.logger.stderr_print(f'Running demeuk - {version}')
    cfg.logger.stderr_print(f'Using {cfg.threads} out of {cpu_count()} available CPUs')


    cfg.logger.write_log(f'Running demeuk - {version}{linesep}')


    with Pool(cfg.threads, init_worker) as pool:
        cfg.logger.stderr_print(f'Reading input file(s)...')

        jobs = []

        if cfg.input_files:
            for file in tqdm(cfg.input_files,
                             desc='Files processed',
                             mininterval=0.5,
                             unit=' files',
                             disable=not cfg.progress,
                             position=0):
                if not access(file, R_OK):
                    continue
                total_chunks = ceil(path.getsize(file) / cfg.chunk_size)
                for chunk in tqdm(chunkify(file, cfg),
                                  desc='Chunks processed',
                                  mininterval=0.5,
                                  unit=' chunks',
                                  disable=not cfg.progress,
                                  total=total_chunks,
                                  position=1):
                    submit(pool, jobs, pipeline, chunk, cfg)
        else:
            # Read from stdin
            chunks = sys.stdin.readlines(cfg.chunk_size)
            while chunks:
                chunk = [line.rstrip('\n').encode(cfg.input_encodings[0]) for line in chunks]
                submit(pool, jobs, pipeline, chunk, cfg)

                chunks = sys.stdin.readlines(cfg.chunk_size)
        cfg.logger.stderr_print('Submitted jobs, waiting for jobs to finish...')

        # Wait for jobs to finish
        finish_up(jobs, cfg)

    cfg.logger.close_files()
    cfg.logger.stderr_print('Done')

    # This returns the list of results, and the logs.
    return cfg.logger.list_results, cfg.logger.list_log