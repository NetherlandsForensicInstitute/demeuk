#!/usr/bin/env python3
# TODO: Might not be important but it looks like there is always a thread running clean_up with no words...?

import sys
from binascii import hexlify
from collections import deque
from glob import glob
from locale import LC_ALL, setlocale
from math import ceil
from os import linesep, access, path, R_OK, F_OK, W_OK
from signal import signal, SIGINT, SIG_IGN
from string import punctuation as string_punctuation
from sys import  stdin, stdout
from time import sleep

from modules.parser import init_parser, parse_order, get_pipeline
from modules.remove import set_delim, set_cut_fields
from multiprocess import cpu_count, Pool  # multiprocess has better serialization capabilities
from tqdm import tqdm

from modules.add import set_punctuation
# Do we want do do imports like this? or add modules.***.func_name everywhere?
from modules.macro import clean_googlengram
from modules.modify import get_input_encoding, set_input_encoding
from modules.util import set_verbose, unset_verbose, stderr
from modules.validate import params_check, params_modify, validate_output_check, \
    validate_output_signature, validate_input_signature, clean_hex, flags_add, params_remove, \
    flags_modify, clean_encode, clean_tab, stderr_print, clean_html, params_add, flags_remove, \
    flags_check

version = '4.6.2'  # TODO increment

CHUNK_SIZE = 1024 * 1024


# lines = a single line
# pipeline = the function pipeline to run
# Pass the args construction, TODO reconsider if this is still needed later
# We pass both the function pipeline and the string representation (order)
#   to figure out the type of module we run.
def clean_up(lines, pipeline, order, args):
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

        # Can we specify the order of the fixed part of the pipeline apart from the implementation?
        # Probably not, because processing the output depends on the output.
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
        counter = 0  # Should we track module type separately?
        for func in pipeline:
            # Run the module first, then process the output later.
            has_param = isinstance(func, list)
            # The name of the (text) option
            opt = order[counter][0] if has_param else order[counter]
            if not stop:
                status, *rest = func[0](line_decoded, func[1]) if has_param else func(line_decoded)
                if opt in flags_check | params_check:
                    msg = rest[0]
                    if not status:
                        # Tripped check module
                        log.append(f'{msg}; {line_decoded}{linesep}')
                        stop = True
                elif opt in flags_modify | params_modify | flags_remove | params_remove:
                    line_decoded, msg = rest
                    if status:
                        if args.debug:
                            log.append(f'{msg}; {line_decoded}{linesep}')
                        # Do we also need have a "re-encode" module type?
                        if opt == '--hex':  # Later we can determine this by looking at object type
                            work_queue.append(line_decoded)
                            stop = True
                        elif opt == '--html':
                            work_queue.append(line_decoded.encode())
                            stop = True

                elif opt in flags_add | params_add:
                    result, msg = rest
                    if status:
                        # We have modified lines
                        if isinstance(result, list):
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
            results.append(f'{line_decoded}{linesep}')

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

    if args.threads:
        a_threads = int(args.threads)
    else:
        a_threads = cpu_count()

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

    input_enc = args.input_encoding if args.input_encoding else 'UTF-8'  # default input-enc.
    set_input_encoding(input_enc)

    if args.output_encoding:
        setlocale(LC_ALL, args.output_encoding)
    else:
        setlocale(LC_ALL, 'en_US.UTF-8')

    if args.punctuation:
        set_punctuation(args.punctuation)
    else:
        set_punctuation(string_punctuation + ' ')

    if args.delimiter:
        set_delim(args.delimiter)
    else:
        set_delim(':')

    if args.cut_before:
        args.cut_fields = '-1'

    # This overrides --cut-before
    if args.cut_fields:
        set_cut_fields(args.cut_fields)
    else:
        set_cut_fields('2-')

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

    # Generate and validate function list
    func_list = get_pipeline(order)
    if not validate_input_signature(order, func_list):
        # (Custom) module takes incorrect input parameters
        return
    # NB: output check is not conclusive. do we want more rigid type checking?
    if not validate_output_check(order, func_list):
        # validate check module
        return
    if not validate_output_signature(order, func_list):
        # validate other modules
        return

    if output_file and not access(path.dirname(output_file), W_OK):
        stderr_print(f"Cannot write output file to {output_file}")

    # check if logfile exists, or that the directory of the log file is at least writable.
    if log_file and not (access(log_file, F_OK) or access(path.dirname(log_file), W_OK)):
        stderr_print(f"Cannot write log file to {log_file}")
    if input_file and not access(input_file, R_OK):
        stderr_print(f"Cannot read input file to {input_file}")

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
                job = pool.apply_async(clean_up, (chunk, func_list, order, args))
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


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        stderr_print("ERROR: Process terminated by user! (CTRL+C)")
        exit(3)
