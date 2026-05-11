from locale import getlocale
from os import access, path, W_OK, F_OK
from sys import stdout, stderr


# Manages file handle to output file
class OutputFileHandler:

    def __init__(self, args, logger):

        encoding = getlocale()[1]
        # Check if we can write to output and log files
        # TODO:Phase out os.access in favour of try/except PermissionError?
        if args.output:
            try:
                self.output_file = open(args.output, 'w', encoding=encoding, newline='') # Overwrite output file
                logger.stderr_print(f'Writing output to {args.output}')
            except PermissionError:
                logger.stderr_print_always(f'Cannot write output file to {args.output}!')
                exit(2)
        else:
            self.output_file = stdout
            logger.stderr_print(f'Writing output to stdout')

    def write(self, lines):
        self.output_file.writelines(lines)
        self.output_file.flush()

    def close(self):
        if self.output_file != stdout:
            self.output_file.close()