from os import linesep
from time import sleep


def chunkify(file, cfg):
    with open(file, 'rb') as fh:
        for x in range(0, cfg.skip):
            fh.readline()

        while True:
            lines = [line.rstrip(linesep.encode()) for line in fh.readlines(cfg.chunk_size)]
            yield lines
            if len(lines) == 0:
                break

def check_finished_jobs(jobs, logger):
    while jobs and jobs[0].ready():
        job = jobs.pop(0)
        logger.write_results(job.get())

def submit(pool, jobs, pipeline, chunk, config):
    while True:
        running_jobs = sum([not job.ready() for job in jobs])
        if running_jobs < config.threads:
            jobs.append(pool.apply_async(pipeline.run, (chunk, config)))
            return
        else:
            # Wait until a thread is available.
            sleep(0.5)

def finish_up(jobs, config):
    while len(jobs) > 0:
        job = jobs.pop(0)
        job.wait()
        # For some reason, sometimes job.wait() continues execution a fraction of a second early
        # Waiting until job.ready() has the same issue.
        # Waiting 8ms to let the thread finish "solves" this problem.
        sleep(8 / 1000)
        config.logger.write_results(job.get())