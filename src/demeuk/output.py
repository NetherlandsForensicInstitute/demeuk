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
                self.output_file = open(args.output, 'w', encoding=encoding, newline='') # Overwrite output file
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