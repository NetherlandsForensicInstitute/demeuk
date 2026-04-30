from unicodedata import category

from chardet import detect
from demeuk.modules.base import Module, PipelinePosition, HelpInfo, HelpInfoParam, Result, Actions, ConfigModule


class EncodeModule(ConfigModule):
    def set_configs(self, config):
        self.add_config('encodings', config.input_encodings)

    @staticmethod
    def get_parser_group() -> str:
        return 'modify'

    @staticmethod
    def get_pipeline_position():
        return PipelinePosition.ENCODE

    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='encode',
            help_str='Enables guessing of encoding, based on chardet and custom implementation.')

    # Only here, this is the success message...
    @property
    def debug_str(self) -> str:
        return f'Clean:\tEncode:\t\tdecoded line'

    @staticmethod
    def _try_encoding(line, encoding):
        """Tries to decode a line using supplied encoding

        Params:
            line (Byte): byte variable that will be decoded
            encoding (string): the encoding to be tried

        Returns:
            False if decoding failed
            String if decoding worked
        """
        try:
            # Try to decode the line
            line_decoded = line.decode(encoding)
            # Some encodings will decode almost any line, let's check if we have invalid chars.
            # If we have invalid chars (except for tab-like chars) we will fail
            for c in line_decoded:
                if category(c) in ['Cc', 'Cf', 'Cn', 'Co', 'Cs']:
                    if c == '\t' or c == '\f':
                        continue
                    else:
                        return False
            return line_decoded
        except UnicodeDecodeError:
            return False

    # Always returns status true, because we either need to update the line OR we have a decoding error.
    def run(self, line):
        for encoding in self.get_config('encodings'):
            result = self._try_encoding(line, encoding)
            if result is not False:
                return Result(status=True, update=result, msg=self.debug_str)
        else:
            # Did not break, so tried all encodings and did not find a valid one.
            # Try chardet
            encode = detect(line)
            if encode.get('encoding'):
                try:
                    decoded_line = line.decode(encode['encoding'])
                    # successful decoding!
                    return Result(status=True, update=decoded_line, msg=self.debug_str)
                except (UnicodeDecodeError, LookupError) as e:
                    return Result(status=True, msg=f'Clean:\tEncode:\t\tdecoding error with {encode['encoding']}')
            else:
                return Result(status=True, msg='Clean:\tEncode:\t\tdecoding error with unknown encoding')

    def handle(self, result):
        if result.update is None:
            # Encoding failed, so stop.
            # Log failure always.
            return Actions(stop=True, log_str=result.msg)
        # Encoding is successful
        return Actions(update=result.update, debug_str=result.msg)


# Dropped in place if --encode is not used
class DefaultEncodeModule(ConfigModule):

    def set_configs(self, config):
        # Get first config, either UTF-8 or user-specified.
        self.add_config('encoding', config.input_encodings[0])

    @property
    def debug_str(self) -> str:
        return 'Clean:\tDefault encode:\tdecoding error'

    def run(self, line):
        try:
            decoded_line = line.decode(self.get_config('encoding'))
            return Result(status=True, update=decoded_line, msg=f'Clean:\tDefault encode:\tdecoded using input encoding {self.get_config('encoding')}')
        except UnicodeDecodeError as e:
            return Result(status=True, msg=self.debug_str)


    # Same as EncodeModule...
    def handle(self, result):
        if result.update is None:
            return Actions(stop=True, log_str=result.msg)
        return Actions(update=result.update, debug_str=result.msg)

    # Need to implement these to instantiate, but they are not used

    # Can't invoke this manually
    @staticmethod
    def get_help_info():
        pass

    # Same as above
    @staticmethod
    def get_parser_group():
        return 'exclude'

    # Pipeline ctor knows where to put this module.
    @staticmethod
    def get_pipeline_position():
        pass


