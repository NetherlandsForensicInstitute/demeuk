from .modify import ModifyModule
from ..base import *

class CutModule(ModifyModule, ConfigModule):
    def set_configs(self, config):
        self.add_config('delims', config.delimiters)
        self.add_config('fields', config.cut_fields)

    @staticmethod
    def get_help_info():
        return HelpInfo(
            option=['c', 'cut'],
            help_str="Specify if demeuk should split (default splits on ':'). Returns everything after the delimiter.")

    def run(self, line):
        fields = self.get_config('fields')
        for delimiter in self.get_config('delims'):
            if delimiter in line:
                if '-' in fields:
                    start = fields.split('-')[0]
                    stop = fields.split('-')[1]
                    if start == '':
                        start = 1
                    if stop == '':
                        stop = len(line)
                    fields = slice(int(start) - 1, int(stop))
                else:
                    fields = slice(int(fields) - 1, int(fields))
                cleaned_line = delimiter.join(line.split(delimiter)[fields])
                return Result(status=True, msg=self.debug_str, update=cleaned_line)
        else:
            return RESULT_NEXT