from locale import getlocale
from sys import stderr


# Manage logging tasks
class Logger:
    """
    Manage logging tasks

    Verbose messages are info messages on program execution, for example a message when all lines are submitted to the pool.
    Debug messages are more detailed, and these log information about the pipeline run (anytime a module returns a Result with status=True, its corresponding debug message is logged).
    """

    def __init__(self, args):
        """
        Open log file, and set logging flags based on command-line arguments
        Keeps a record of the log, to write it only once per chunk.
        :param args: Parsed command-line arguments
        """
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
            self.stderr_print('Logger: writing log to stderr')

        self.logs = []

    # Do we want to separate stderr print and log_verbose?
    def stderr_print(self, *args, **kwargs):
        """
        Print a message to stderr when --verbose is set.
        :param args: The message to print
        :param kwargs: Any kwargs to pass to print.
        """
        if self.verbose:
            Logger.stderr_print_always(*args, **kwargs)

    def log(self, msg):
        """
        Add a line to the log record
        :param msg: The message to log
        """
        self.logs.append(msg)

    def log_debug(self, msg):
        """
        Add a line to the log record if --debug is set
        :param msg: The message to log
        """
        if self.debug:
            self.logs.append(msg)

    def log_verbose(self, msg):
        """
        Add a line to the log record if --verbose is set
        :param msg: The message to log
        """
        if self.verbose:
            self.logs.append(msg)

    def get(self):
        """
        Get the log record
        :return: A list of strings containing the logs
        """
        return self.logs


    def write(self, lines):
        """
        Write (and flush) a batch of lines to the logfile
        :param lines: A list of lines (with explicit newlines)
        """
        if self.debug or self.verbose or (self.log_file is not stderr):
            self.log_file.writelines(lines)
            self.log_file.flush()


    # Print to stderr always, use for errors or incorrect input
    @staticmethod
    def stderr_print_always(*args, **kwargs):
        """
        Print a message to stderr
        :param args: The message to print
        :param kwargs: Any kwargs to pass to print
        """
        kwargs.setdefault('file', stderr)
        print(*args, **kwargs)

    def close(self):
        """
        Close the file handle to the log file
        """
        if self.log_file != stderr:
            self.log_file.close()