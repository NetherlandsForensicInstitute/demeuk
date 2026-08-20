from glob import glob
from locale import LC_ALL, setlocale
from os import R_OK, access, cpu_count
from string import punctuation as string_punctuation

from .logger import Logger
from .output import OutputFileHandler


# This class carries global configuration, so configurations which either:
#       do not impact the functionality of the modules directly.
# or:   do impact modules, but cannot be passed as a parameter
class Config:
    """
    A class containing all configuration for demeuk
    """

    # Initialize config with argparse output
    def __init__(self, args):
        """
        Initialize config based on command-line arguments
        :param args: Parsed command line arguments, available in CommandLineParser.args after calling parse_args()
        """
        # I/O
        self.input_files = args.input
        self.output_file = args.output
        self.log_file = args.log

        # Verbosity
        self.progress = args.progress
        self.verbose = args.verbose
        self.debug = args.debug

        # Encodings (set these before logger, as logger opens output files)
        self.input_encodings = args.input_encoding.split(',') if args.input_encoding else ['UTF-8']

        if args.output_encoding is not None:
            setlocale(LC_ALL, args.output_encoding)
        else:
            setlocale(LC_ALL, 'en_US.UTF-8')

        self.logger = Logger(args)

        self.output_fh = OutputFileHandler(args, self.logger)

        # Check if we can read input file
        if args.input:
            # args.input is a list (nargs *)
            if len(args.input) > 1:
                # Pass multiple files through command-line
                self.input_files = args.input
            else:
                self.input_files = glob(args.input[0], recursive=True)

            for input_file in self.input_files:
                if not access(input_file, R_OK):
                    self.logger.stderr_print_always(f'Config: Cannot read input file from {input_file}!')


        if self.progress:
            if self.verbose or self.debug:
                if not self.log_file:
                    self.logger.stderr_print_always('Config: --progress cannot be used with --verbose or --debug!')
                    exit(2)
            if not self.input_files:
                self.logger.stderr_print_always('Config: --progress cannot be used when using stdin!')
                exit(2)

        # Other configurations here, with defaults
        self.threads = int(args.threads) if args.threads else cpu_count()
        self.chunk_size = 1024 * 1024
        self.skip = args.skip if args.skip else 0
        self.limit = args.limit
        # NB: a space in the punctiation list is not supported
        self.punctuation = args.punctuation if args.punctuation else string_punctuation + ' '

        # Delimiter determination
        # config.delimiter is a list.
        if args.delimiter:
            splitter = ','
            # We can have comma as delimiter, if we put it first and separate with semicolon.
            if len(args.delimiter) >= 1:
                if args.delimiter[0] == ',':
                    splitter = ';'
            self.delimiters = args.delimiter.split(splitter)
        else:
            self.delimiters = [':']

        # Config for cut
        self.cut_fields = '2-'
        if args.cut_before:
            self.cut_fields = '-1'
        if args.cut_fields:
            # --cut-fields overrides --cut-before
            self.cut_fields = args.cut_fields

        self.cut_before = True if args.cut_before else False


