# Handle debug logging, but also writing the output to file.
from locale import getlocale
from os import access, path, W_OK, F_OK
from sys import stdout, stderr


# Manages file handles to output and log files
class Logger:

    def __init__(self, args):

        # verbosity
        self.verbose = args.verbose
        self.debug = args.debug


        encoding = getlocale()[1]
        # Check if we can write to output and log files
        # TODO:Phase out os.access in favour of try/except PermissionError?
        if args.output:
            try:
                self.output_file = open(args.output, 'w', encoding=encoding, newline='') # Overwrite output file
                self.stderr_print(f'Logger: writing output to {args.output}')
            except PermissionError:
                self.stderr_print_always(f'Logger: Cannot write output file to {args.output}!')
                exit(2)
        else:
            self.output_file = stdout
            self.stderr_print(f'Logger: writing output to stdout')

        if args.log:
            # Check if logfile exists, or that the directory is at least writable.
            if not (access(path.dirname(args.log), W_OK) or access(args.log, F_OK)):
                self.stderr_print_always(f'Logger: Cannot write log file to {args.log}!')
                exit(2)
            self.log_file = open(args.log, 'a', encoding=encoding, newline='') # Append to log file
            self.stderr_print(f'Logger: writing log to {args.log}')
        else:
            self.log_file = stderr
            self.stderr_print(f'Logger: writing log to stderr')

        # A dict of logs.
        self.logs = {}

        self.list_results = []
        self.list_log = []


    def create(self, log):
        self.logs[log] = []

    def stderr_print(self, *args, **kwargs):
        if self.verbose:
            Logger.stderr_print_always(*args, **kwargs)

    def log(self, log, msg):
        self.logs[log].append(msg)

    def log_debug(self, log, msg):
        if self.debug:
            self.logs[log].append(msg)

    def log_verbose(self, log, msg):
        if self.verbose:
            self.logs[log].append(msg)

    def get(self, log):
        return self.logs[log]


    def write_out(self, lines):
        self.output_file.writelines(lines)
        self.output_file.flush()

    def write_log(self, lines):
        if self.debug or self.verbose or (self.log_file is not stderr):
            self.log_file.writelines(lines)
            self.log_file.flush()

    def write_results(self, async_result):
        self.write_out(async_result['results'])
        self.write_log(async_result['log'])

        #self.list_results += [word.rstrip('\n') for word in async_result['results']]
        #self.list_log += [word.rstrip('\n') for word in async_result['log']]

    # Print to stderr always, use for errors or incorrect input
    @staticmethod
    def stderr_print_always(*args, **kwargs):
        kwargs.setdefault('file', stderr)
        print(*args, **kwargs)

    def close_files(self):
        if self.output_file != stdout:
            self.output_file.close()
        if self.log_file != stderr:
            self.log_file.close()