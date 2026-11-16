import sys
from locale import getlocale

from tqdm import tqdm


class Logger:
    """Write progress and ordered worker logs in the parent process."""

    def __init__(self, args, show_progress):
        # Verbose messages are info messages on program execution.
        self.verbose = args.verbose
        # Debug messages are more detailed, and log information about the pipeline run.
        self.debug = args.debug
        self.show_progress = show_progress
        self.log_file = None

        if args.log:
            try:
                self.log_file = open(args.log, 'a+', encoding=getlocale()[1], newline='')
            except PermissionError:
                print(f'Logger: Cannot write log file to {args.log}!', file=sys.stderr)
                raise SystemExit(2)
        else:
            self.progress('Logger: writing log to stderr')

    def progress(self, message):
        # A wrapper function to write a log message, so that it does not interfere with tqdm's progress bars.
        if self.verbose:
            if self.show_progress:
                tqdm.write(message, file=sys.stderr)
            else:
                print(message, file=sys.stderr)

    def write(self, lines):
        if self.debug or self.verbose or self.log_file is not None:
            stream = self.log_file if self.log_file is not None else sys.stderr
            if self.show_progress and self.log_file is None:
                message = ''.join(lines)
                if message:
                    tqdm.write(message, file=stream, end='')
            else:
                stream.writelines(lines)
            stream.flush()

    def close(self):
        if self.log_file is not None:
            self.log_file.close()
