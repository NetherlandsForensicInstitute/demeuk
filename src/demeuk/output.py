from locale import getlocale
from sys import stdout


# Manages file handle to output file
class OutputFileHandler:
    """
    Manage the output file
    """

    def __init__(self, args, logger):
        """
        Open the output file
        :param args:
        :param logger:
        """
        encoding = getlocale()[1]
        if args.output:
            try:
                # Open in write mode to overwrite file if it exists, and close immediately.
                open(args.output, 'w').close()
                # Now open it in append mode, this solves a bug where file writes would get dropped unexpectedly
                self.output_file = open(args.output, 'a', encoding=encoding, newline='') # Now
                logger.stderr_print(f'Writing output to {args.output}')
            except PermissionError:
                logger.stderr_print_always(f'Cannot write output file to {args.output}!')
                exit(2)
        else:
            self.output_file = stdout
            logger.stderr_print('Writing output to stdout')

    def write(self, lines):
        """
        Write (and flush) lines to the output file
        :param lines: A list of lines (with newlines) to write to the output file
        """
        self.output_file.writelines(lines)
        self.output_file.flush()

    def close(self):
        """
        Close the file handle to the output file
        """
        if self.output_file != stdout:
            self.output_file.close()