#!/usr/bin/env python3

import sys
from binascii import hexlify
from collections import deque
from glob import glob
from locale import LC_ALL, setlocale
from math import ceil
from os import F_OK, R_OK, W_OK, access, linesep, path
from signal import SIG_IGN, SIGINT, signal
from sys import stdin, stdout
from time import sleep

from multiprocess import Pool, cpu_count  # multiprocess can serialize the inner functions in clean_up
from tqdm import tqdm

from .modules.macro import clean_googlengram
from .util import *
from .validate import *


version = '4.7.0'

CHUNK_SIZE = 1024 * 1024


# lines = a single line
# pipeline = the function pipeline to run
# Pass the args construction, TODO reconsider if this is still needed later
# We pass both the function pipeline and type info
#   so that we don't have to figure out the type of module we run every loop.
def clean_up(lines, pipeline, type_info, args):
    """Main clean loop, this calls all the other clean functions.

    Args:
        line(bytes): Line to be cleaned up

    Returns:
        (str(Decoded line), str(Failed line))
    """
    results = []
    log = []
    processed_lines = set()
    work_queue = deque(lines)

    while work_queue:
        line = work_queue.popleft()

        if line in processed_lines:
            continue
        processed_lines.add(line)

        # Check if the limit is set, if so minus 1 and if 0 is reached lets quit.
        if args.limit is not None:
            if args.limit > 0:
                args.limit -= 1
            else:
                break

        # When stop is set all demeuking module will be skipped for this line.
        stop = False
        if args.debug:
            log.append(f'----BEGIN---- {hexlify(line)}{linesep}')

        # First, execute the fixed part of the pipeline.

        # Replace tab chars as ':' greedy
        if args.tab and not stop:
            status, line, msg = clean_tab(line)
            if status and args.debug:
                log.append(f'{msg}; {line}{linesep}')

        # Converting encoding to UTF-8
        if args.encode and not stop:
            status, line_decoded = clean_encode(line)
            if status is False:
                log.append(f'Clean_encode; decoding error with {line_decoded}; {line}{linesep}')
                stop = True
            elif status is True and args.debug:
                log.append(f'Clean_encode; decoded line; {line_decoded}{linesep}')
        else:
            try:
                # If no encoding specified, assume UTF-8
                line_decoded = line.decode(get_input_encoding()[0])
                if args.debug:
                    log.append(
                        f'Clean_up; decoded using input_encoding option; {line_decoded}{linesep}')
            except (UnicodeDecodeError) as e:  # noqa F841
                log.append(f'Clean_up; decoding error with unknown; {line}{linesep}')
                stop = True
        # From here it is expected that line is correctly decoded!

        # Check if some lines contain a hex string like $HEX[41424344]
        if args.hex and not stop:
            status, line_decoded, msg = clean_hex(line_decoded)
            if status:
                # Lines contains hex, this function will return binary string, so add it back to our undecoded lines
                work_queue.append(line_decoded)
                if args.debug:
                    log.append(f'{msg}; {line}{linesep}')
                # Aborting future processing of this line.
                stop = True

        # Check if there are html char in the line, decode them if there are
        if args.html and not stop:
            status, line_decoded, msg = clean_html(line_decoded)
            if status:
                # Line contains html string, because this can be binary data (linefeeds etc)
                # convert back to binary string and add to queue again.
                work_queue.append(line_decoded.encode())
                if args.debug:
                    log.append(f'{msg}; {line_decoded}{linesep}')
                stop = True

        if args.googlengram and not stop:
            status, line_decoded, msg = clean_googlengram(line_decoded)
            if status and args.debug:
                log.append(f'{msg}; {line_decoded}{linesep}')

        # This is where the order-dependent modules (non-fixed pipeline) run
        counter = 0
        for func in pipeline:
            # First: check if we need to do anything
            if not stop:
                option_type, module_type = type_info[counter]
                if option_type == OptionType.FLAG:
                    status, *rest = func(line_decoded)
                else:
                    # option_type = OptionType.PARAM
                    func, param = func
                    status, *rest = func(line_decoded, param)

                # Status is true if something happened, false if nothing changed
                if status:
                    if module_type == ModuleType.CHECK:
                        msg = rest[0]
                        log.append(f'{msg}; {line_decoded}{linesep}')
                        stop = True
                    elif module_type in [ModuleType.MODIFY, ModuleType.REMOVE]:
                        line_decoded, msg = rest
                        if args.debug:
                            log.append(f'{msg}; {line_decoded}{linesep}')
                    elif module_type == ModuleType.ADD:
                        result, msg = rest
                        if isinstance(result, list):
                            # We have to add multiple lines
                            for new_line in result:
                                if args.debug:
                                    log.append(f'{msg}; {new_line}{linesep}')
                                work_queue.append(new_line.encode())
                        else:
                            # The result is a string
                            if args.debug:
                                log.append(f'{msg}; {result}{linesep}')
                            work_queue.append(result.encode())

            counter += 1

        # If we got through the whole function pipeline:
        if not stop:
            results.append(f'{line_decoded}{linesep}')  # include the line in the output.
            if args.debug:
                log.append(f'----END---- {line_decoded}{linesep}{linesep}')

    return {'results': results, 'log': log}


def chunkify(filename, args, size=CHUNK_SIZE):
    with open(filename, 'rb') as fh:
        if args.skip:
            for x in range(0, args.skip):
                fh.readline()

        while True:
            lines = [line.rstrip(b'\n') for line in fh.readlines(size)]
            yield lines
            if len(lines) == 0:
                break


def main():
    # Initialize and get arguments
    arg_parser = init_parser(version)
    args = arg_parser.parse_args()

    # Configure program based on args
    input_file = args.input
    output_file = args.output
    log_file = args.log

    if args.verbose:
        set_verbose()
    else:
        unset_verbose()

    if args.progress:
        if args.verbose or args.debug:
            if not log_file:
                stderr_print('Progress can not be used with verbose or debug')
                exit(2)
        if not input_file:
            # Forcing printing error message
            args.verbose = True
            stderr_print('Progress can not be used when using stdin.')
            exit(2)

    # Set config options with defaults
    a_threads = int(args.threads) if args.threads else cpu_count()
    set_input_encoding(args.input_encoding if args.input_encoding else 'UTF-8')
    setlocale(LC_ALL, args.output_encoding if args.output_encoding else 'en_US.UTF-8')
    set_punctuation(args.punctuation if args.punctuation else string_punctuation + ' ')
    set_delim(args.delimiter if args.delimiter else ':')

    if args.cut_before:
        args.cut_fields = '-1'

    # This overrides --cut-before
    set_cut_fields(args.cut_fields if args.cut_fields else '2-')

    # Some meta-modules
    # For googlengram: These disable some modules, even if they are passed as cmd-line args.
    if args.googlengram:
        args.cut = False
        args.remove_email = False
        args.encode = True
        args.mojibake = False
        args.check_controlchar = False
        args.tab = False

    # Meta-module for leak files. Set the following defaults:
    # mojibake, encode, newline, check-controlchar
    if args.leak:
        args.mojibake = True
        args.encode = True
        args.newline = True
        args.check_controlchar = True

    # Meta-module for leak fils, but more modules. Set the following defaults:
    # --mojibake, --encode, --newline, --check-controlchar,
    # --hex, --html, --html-named,
    # --check-hash, --check-mac-address, --check-uuid, --check-email,
    # --check-replacement-character, --check-empty-line
    if args.leak_full:
        args.mojibake = True
        args.encode = True
        args.newline = True
        args.check_controlchar = True
        args.hex = True
        args.html = True
        args.html_named = True
        args.check_hash = True
        args.check_mac_address = True
        args.check_uuid = True
        args.check_email = True
        args.check_replacement_character = True
        args.check_empty_line = True

    # Merge -c and --cut options (TODO actually we don't want to do this manually)
    if args.c or args.cut:
        args.c = True
        args.cut = True

    # Determine order of modules (NB: need to do this when the pipeline is finalized)
    # so after processing "grouping" modules like leak and leak-full
    order = parse_order(sys.argv)
    type_info = get_type_info(order)

    # Generate and validate function list
    pipeline = get_pipeline(order)
    if not validate_input_signature(order, pipeline):
        # (Custom) module takes incorrect input parameters
        return
    if not validate_output_signature(order, pipeline):
        # validate (number of) return values of module
        return

    if output_file and not access(path.dirname(output_file), W_OK):
        stderr_print(f'Cannot write output file to {output_file}')

    # check if logfile exists, or that the directory of the log file is at least writable.
    if log_file and not (access(log_file, F_OK) or access(path.dirname(log_file), W_OK)):
        stderr_print(f'Cannot write log file to {log_file}')
    if input_file and not access(input_file, R_OK):
        stderr_print(f'Cannot read input file to {input_file}')

    #  Main worker
    stderr_print(f'Main: running demeuk - {version}')

    stderr_print(f'Main: Using {a_threads} core(s) of total available cores: {cpu_count()}')

    stderr_print(f'Main: start chunking file {input_file}')
    if output_file:
        stderr_print(f'Main: output found in {output_file}')
    if log_file:
        stderr_print(f'Main: logs found in {log_file}')

    stderr_print('Main: done chunking file.')
    stderr_print('Main: processing started.')

    if output_file:
        p_output_file = open(output_file, 'w')
    else:
        p_output_file = stdout

    if log_file:
        p_log_file = open(log_file, 'a')
    else:
        p_log_file = stderr

    def write_results(results):
        p_output_file.writelines(results)
        p_output_file.flush()

    def write_log(log):
        if args.debug or args.verbose or log_file:
            p_log_file.writelines(log)
            p_log_file.flush()

    def write_results_and_log(async_result):
        write_results(async_result['results'])
        write_log(async_result['log'])

    def init_worker():
        signal(SIGINT, SIG_IGN)

    def process_jobs(chunk_start):
        # Cut file in to chunks and process each trunk multi-threaded
        while True:
            while True:
                # Process completed jobs in-order
                if jobs and jobs[0].ready():
                    # Housekeeping cleanup jobs completed from the list
                    job = jobs.pop(0)
                    write_results_and_log(job.get())
                else:
                    break

            # Find out which jobs are running
            running_jobs = sum([not job.ready() for job in jobs])
            if running_jobs < a_threads:
                job = pool.apply_async(clean_up, (chunk, pipeline, type_info, args))
                chunk_start += len(chunk)
                jobs.append(job)
                break
            else:
                # Wait a little while for available spacing within Pool
                sleep(1)

    write_log(f'Running demeuk - {version}{linesep}')
    with Pool(a_threads, init_worker) as pool:
        jobs = []
        # chunk_start will be the started value of the combined output lines
        chunk_start = 0
        if input_file:
            # Process files based on input glob
            for filename in tqdm(glob(input_file, recursive=True), desc='Files processed',
                                 mininterval=0.1,
                                 unit=' files', disable=not args.progress, position=0):
                if not access(filename, R_OK):
                    continue
                chunks_estimate = int(ceil(path.getsize(filename) / CHUNK_SIZE))
                for chunk in tqdm(chunkify(filename, args, CHUNK_SIZE), desc='Chunks processed',
                                  mininterval=1,
                                  unit=' chunks', disable=not args.progress, total=chunks_estimate,
                                  position=1):
                    process_jobs(chunk_start)
            stderr_print('Main: done submitting all jobs, waiting for threads to finish')
            while len(jobs) > 0:
                job = jobs.pop(0)
                job.wait()
                write_results_and_log(job.get())
        else:
            # Read chunk amount from stdin
            chunks = stdin.readlines(CHUNK_SIZE)
            while chunks:
                chunk = [line.rstrip('\n').encode(get_input_encoding()[0]) for line in chunks]
                process_jobs(chunk_start)

                chunks = stdin.readlines(CHUNK_SIZE)

            stderr_print('Main: done submitting all jobs, waiting for threads to finish')
            while len(jobs) > 0:
                job = jobs.pop(0)
                job.wait()
                write_results_and_log(job.get())

    stderr_print('Main: all done')
    if output_file:
        p_output_file.close()
    if log_file:
        p_log_file.close()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        stderr_print('ERROR: Process terminated by user! (CTRL+C)')
        exit(3)


def get_version():
    return version
