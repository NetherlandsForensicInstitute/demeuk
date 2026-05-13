from os import linesep
from signal import SIG_IGN, SIGINT, signal
from time import sleep


"""
Utility functions for multiprocessing and chunking input files
"""

def init_worker():
    signal(SIGINT, SIG_IGN)

def chunkify(file, cfg):
    """
    Split a file into chunks, to pass onto the module pipeline
    :param file: File to split
    :param cfg: Config object, needed for skip and chunk_size.
    """
    with open(file, 'rb') as fh:
        for x in range(0, cfg.skip):
            fh.readline()

        while True:
            lines = [line.rstrip(linesep.encode()) for line in fh.readlines(cfg.chunk_size)]
            yield lines
            if len(lines) == 0:
                break

def check_finished_jobs(jobs, config):
    """
    Check jobs queue for any finished jobs
    :param jobs:    Jobs queue
    :param logger:  Logger object
    """
    while jobs and jobs[0].ready():
        job = jobs.pop(0)
        write_results(config.output_fh, config.logger, job.get())

def submit(pool, jobs, pipeline, chunk, config):
    """
    Submit a chunk of lines to the multiprocessing pool.
    :param pool: Multiprocessing pool
    :param jobs: Jobs queue
    :param pipeline: Pipeline to run
    :param chunk: List of lines to demeuk
    :param config: Config object
    """
    while True:
        running_jobs = sum([not job.ready() for job in jobs])
        if running_jobs < config.threads:
            jobs.append(pool.apply_async(pipeline.run, (chunk, config)))
            return
        else:
            # Wait until a thread is available.
            sleep(0.5)

def finish_up(jobs, config):
    """
    Wait for jobs to finish and write results.
    :param jobs: Jobs queue
    :param config: Config object.
    """
    while len(jobs) > 0:
        job = jobs.pop(0)
        job.wait()
        # For some reason, sometimes job.wait() continues execution a fraction of a second early
        # Waiting until job.ready() has the same issue.
        # Waiting 8ms to let the thread finish "solves" this problem.
        sleep(8 / 1000)
        write_results(config.output_fh, config.logger, job.get())

def write_results(output_fh, logger, async_result):
    output_fh.write(async_result['results'])
    logger.write(async_result['log'])
