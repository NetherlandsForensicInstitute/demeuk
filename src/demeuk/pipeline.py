from collections import deque
from os import linesep

from demeuk.modules.base import ParamModule, Actions


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

    # This is one worker job, process a list of lines.
    def run(self, lines, logger):
        results = []
        log = []
        processed_lines = set()
        work_queue = deque(lines)

        while work_queue:
            line = work_queue.popleft()

            if line in processed_lines:
                continue
            processed_lines.add(line)


            # Could be done with continue?
            stop = False


            # If no encoding specified, assume UTF-8
            try:
                line_decoded = line.decode('UTF-8')
                if logger.debug:
                    log.append(f'Clean_up; decoded using input_encoding option; {line_decoded}{linesep}')
            except (UnicodeDecodeError) as e:  # noqa F841
                log.append(f'Clean_up; decoding error with unknown; {line}{linesep}')
                continue

            for module in self.modules:
                if not stop:
                    result = module.run(line_decoded)
                    if result.status:
                        # Handle module result
                        actions = module.handle(result)

                        stop = actions.stop
                        if actions.log_str is not None:
                            log.append(f'{actions.log_str}; {line_decoded}{linesep}')
                        if actions.debug_str is not None:
                            if logger.debug:
                                log.append(f'{actions.debug_str}; {line_decoded}{linesep}')


            # If we got through all the modules:
            if not stop:
                results.append(f'{line}{linesep}')

        return {'results': results, 'log': log}



