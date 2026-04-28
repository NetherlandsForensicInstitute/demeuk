from demeuk.modules.base import ParamModule


class Pipeline:
    def __init__(self, parser, argv):
        self.modules = []

        for i in range(1, len(argv)):
            current_arg = argv[i]
            if current_arg in parser.lookup_table:
                module = parser.lookup_table[current_arg]
                if issubclass(module, ParamModule):
                    # Instantiate with param
                    self.modules.append(module(argv[i + 1]))
                else:
                    # Instantiate a module without parameters
                    self.modules.append(module())
