from .modify import ModifyModule
from ..base import *


class NewlineModule(ModifyModule):
    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='newline',
            help_str="Enables removing newline characters ('\\r' and '\\n') from end and beginning of lines.")

    def run(self, line):
        cleaned_line = line.strip('\r\n')
        return self.get_result(line, cleaned_line)


class TrimModule(ModifyModule):
    TRIM_BLOCKS = ('\\\\n', '\\\\r', '\\n', '\\r', '<br>', '<br />')

    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='trim',
            help_str="Remove whitespace from beginning and end of line. Whitespace detected is '\\\\n', '\\\\r', '\\n', '\\r', '<br>' and '<br />'."
        )

    def run(self, line):
        cleaned_line = line
        # Ensure removal of duplicated blocks
        while True:
            has_match = False
            for x in self.TRIM_BLOCKS:
                if cleaned_line.startswith(x):
                    cleaned_line = cleaned_line[len(x):]
                    has_match = True

                if cleaned_line.endswith(x):
                    cleaned_line = cleaned_line[:-len(x)]
                    has_match = True

            if not has_match:
                break

        return self.get_result(line, cleaned_line)


class TabModule(ModifyModule):
    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='tab',
            help_str="Enables replacing tab char with ':', sometimes leaks contain both ':' and '\\t'."
        )

    # This module runs on bytes
    @staticmethod
    def get_pipeline_position():
        return PipelinePosition.BEFORE_ENCODE

    def run(self, line):
        if b'\x09' in line:
            line = sub(b'\x09+', b'\x3a', line)
            return Result(status=True, msg=self.debug_str, update=line)
        return Result(status=False, msg=None)
