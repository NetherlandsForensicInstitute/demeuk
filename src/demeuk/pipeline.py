from binascii import hexlify
from collections import deque
from os import linesep

from .modules.base import *
from .modules.macro import MacroModule
from .modules.encode import DefaultEncodeModule


class Pipeline:
    def __init__(self, parser, argv, config):

        # Keep track where our encoding module (should) be
        self.has_encoding = False
        self.encoding_slot = 0

        self.modules = []


        # Build pipeline
        for i in range(1, len(argv)):
            current_arg = argv[i]
            if current_arg in parser.lookup_table:
                module = parser.lookup_table[current_arg]
                if issubclass(module, ParamModule):
                    # Instantiate with param
                    instance = module(argv[i + 1])
                else:
                    # Instantiate a module without parameters
                    instance = module()

                if issubclass(module, ConfigModule):
                    instance.set_configs(config)

                # Currently, the submodules are placed BEFORE the macro module.
                # Does this matter?
                if issubclass(module, MacroModule):
                    for subinstance in instance.get_submodules():
                        self.include_module(subinstance)


                self.include_module(instance)


        # --encode not used
        if not self.has_encoding:
            # Insert the standard encoder (is a config module)
            default_encode = DefaultEncodeModule()
            default_encode.set_configs(config)
            self.modules.insert(self.encoding_slot, default_encode)


    # Include module at right point of pipeline
    def include_module(self, instance):
        # Append, insert at 0 or insert at encoding_slot?
        match instance.get_pipeline_position():
            case PipelinePosition.BEFORE_ENCODE:
                self.modules.insert(self.encoding_slot, instance)
                # Bump up encoding slot. Also makes sure BEFORE_ENCODE modules are placed in order.
                self.encoding_slot += 1
            case PipelinePosition.ENCODE:
                self.modules.insert(self.encoding_slot, instance)
                self.has_encoding = True
                # don't need to keep track of encoding_slot if inserted.
            case PipelinePosition.AFTER_ENCODE:
                self.modules.append(instance)

    # This is one worker job, process a list of lines.
    def run(self, lines, config):
        results = []
        log_id = 0
        logger = config.logger
        logger.create(log_id) # TODO auto-increment per call of run()
        processed_lines = set()
        work_queue = deque(lines)

        while work_queue:
            line = work_queue.popleft()

            if line in processed_lines:
                continue
            processed_lines.add(line)


            # Could be done with continue?
            stop = False
            logger.log_debug(log_id, f'----BEGIN---- {hexlify(line)}{linesep}')



            for module in self.modules:
                if not stop:
                    result = module.run(line)
                    if result.status:
                        # Transform module result into actions
                        actions = module.handle(result)

                        stop = actions.stop

                        # Perform actions if they are set

                        if actions.add is not None:
                            # Add (a list of) word(s) to the queue
                            for word in actions.add:
                                if actions.do_not_re_encode:
                                    work_queue.append(word) # for --hex
                                else:
                                    work_queue.append(word.encode())
                                if actions.debug_add_str is not None:
                                    logger.log_debug(log_id, f"{module.__class__.__name__}:\t{actions.debug_add_str}:\t{word}{linesep}")

                        if actions.update is not None:
                            line = actions.update

                        if actions.log_str is not None:
                            # Log a message (always)
                            logger.log(log_id, f"{module.__class__.__name__}:\t{actions.log_str}:\t{line}{linesep}")
                        if actions.debug_str is not None:
                            # Log a message (with --debug)
                            logger.log_debug(log_id, f"{module.__class__.__name__}:\t{actions.debug_str}:\t{line}{linesep}")

            # If we got through all the modules:
            if not stop:
                results.append(f'{line}{linesep}')
                logger.log_debug(log_id, f'-----END----- {line}{linesep}{linesep}')

        return {'results': results, 'log': logger.get(log_id)}



