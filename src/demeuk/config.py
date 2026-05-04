from locale import setlocale, LC_ALL
from os import cpu_count, R_OK, access
from string import punctuation as string_punctuation

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

        # Encodings (set these before logger, as logger opens output files)
        self.input_encodings = args.input_encoding.split(',') if args.input_encoding else ['UTF-8']

        if args.output_encoding is not None:
            setlocale(LC_ALL, args.output_encoding)
        else:
            setlocale(LC_ALL, 'en_US.UTF-8')

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
        self.chunk_size = 1024 * 1024 # TODO do we want to be able to change this?
        self.skip = args.skip if args.skip else 0
        self.limit = args.limit
        # TODO can we supply punctuation with space?
        self.punctuation = args.punctuation if args.punctuation else string_punctuation + ' '

        # Delimiter determination
        # config.delimiter is a list.
        if args.delimiter:
            splitter = ','
            # We can have comma as delimiter, if we put it first and separate with semicolon.
            # TODO add test for this
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


