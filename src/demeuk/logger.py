from locale import getlocale
from os import access, path, W_OK, F_OK
from sys import stdout, stderr


# Manage logging tasks
class Logger:

    def __init__(self, args):

        # verbosity
        self.verbose = args.verbose
        self.debug = args.debug


        encoding = getlocale()[1]
        # Check if we can write to output and log files
        if args.log:
            try:
                self.log_file = open(args.log, 'a+', encoding=encoding, newline='') # Append or write
            except PermissionError:
                self.stderr_print_always(f'Logger: Cannot write log file to {args.log}!')
                exit(2)
        else:
            self.log_file = stderr
            self.stderr_print(f'Logger: writing log to stderr')

        self.logs = []

    # Do we want to separate stderr print and log_verbose?
    def stderr_print(self, *args, **kwargs):
        if self.verbose:
            Logger.stderr_print_always(*args, **kwargs)

    def log(self, msg):
        self.logs.append(msg)

    def log_debug(self, msg):
        if self.debug:
            self.logs.append(msg)

    def log_verbose(self, msg):
        if self.verbose:
            self.logs.append(msg)

    def get(self):
        return self.logs


    def write(self, lines):
        if self.debug or self.verbose or (self.log_file is not stderr):
            self.log_file.writelines(lines)
            self.log_file.flush()


    # Print to stderr always, use for errors or incorrect input
    @staticmethod
    def stderr_print_always(*args, **kwargs):
        kwargs.setdefault('file', stderr)
        print(*args, **kwargs)

    def close(self):
        if self.log_file != stderr:
            self.log_file.close()