import sys
from glob import glob
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

    cfg.logger.stderr_print(f'Running demeuk - {version}')
    cfg.logger.stderr_print(f'Using {cfg.threads} out of {cpu_count()} available CPUs')


    cfg.logger.write_log(f'Running demeuk - {version}{linesep}')


    with Pool(cfg.threads, init_worker) as pool:
        cfg.logger.stderr_print(f'Chunking file {cfg.input_file}')

        jobs = []

        if cfg.input_file:
            for file in tqdm(glob(cfg.input_file, recursive=True),
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
            # Submit all job with stdin...
            pass
        cfg.logger.stderr_print('Submitted jobs, waiting for jobs to finish...')

        # Wait for jobs to finish
        finish_up(jobs, cfg)

    cfg.logger.close_files()
    cfg.logger.stderr_print('Done')