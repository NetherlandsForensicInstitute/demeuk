from time import sleep


def chunkify(cfg):
    with open(cfg.input_file, 'rb') as fh:
        for x in range(0, cfg.skip):
            fh.readline()

        while True:
            lines = [line.rstrip(b'\n') for line in fh.readlines(cfg.chunk_size)]
            yield lines
            if len(lines) == 0:
                break

def submit(pool, jobs, pipeline, chunk, config):
    while True:
        running_jobs = sum([not job.ready() for job in jobs])
        if running_jobs < config.threads:
            jobs.append(pool.apply_async(pipeline.run, (chunk, config)))
            return
        else:
            # Wait until a thread is available.
            sleep(0.5)