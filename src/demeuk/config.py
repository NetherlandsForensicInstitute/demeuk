from os import cpu_count, R_OK, access

from demeuk.logger import Logger


# This class carries global configuration, so configurations which either:
#       do not impact the functionality of the modules directly.
# or:   do impact modules, but cannot be passed as a parameter
class Config:

    # Initialize config with argparse output
    def __init__(self, args):
        # I/O
        self.input_file = args.input
        self.output_file = args.output
        self.log_file = args.log

        # Verbosity
        self.progress = args.progress
        self.verbose = args.verbose
        self.debug = args.debug

        print(args)
        self.logger = Logger(args)

        # Check if we can read input file (output files are checked by logger ctor)
        if args.input:
            if not access(args.input, R_OK):
                Logger.stderr_print_always(f'Config: Cannot read input file from {args.input}!')


        if self.progress:
            if self.verbose or self.debug:
                if not self.log_file:
                    Logger.stderr_print_always('Config: --progress cannot be used with --verbose or --debug!')
                    exit(2)
            if not self.input_file:
                Logger.stderr_print_always('Config: --progress cannot be used when using stdin!')
                exit(2)

        # Other configurations here, with defaults
        self.threads = int(args.threads) if args.threads else cpu_count()

        # List
        self.input_encodings = args.input_encoding.split(',') if args.input_encoding else ['UTF-8']

