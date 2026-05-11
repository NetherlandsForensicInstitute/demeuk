from html import unescape

from ftfy.chardata import HTML_ENTITY_RE, HTML_ENTITIES
from .modify import ModifyModule
from ..base import *

class HtmlModule(ModifyModule):
    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='html',
            help_str='Replace lines like: &#351;ifreyok with şifreyok.')

    @property
    def debug_str(self):
        return 'replaced HTML, added to queue and quitting'

    @staticmethod
    def _unescape_fixup(match):
        """
        Replace one matched HTML entity with the character it represents,
        if possible.

        Based on: ftfy.fixes._unescape_fixup
        """
        text = match.group(0)
        if text.startswith('&#'):
            unescaped = unescape(text)

            # If html.unescape only decoded part of the string, that's not what we want. The semicolon should be consumed.
            if ';' in unescaped:
                return text
            else:
                return unescaped
        else:
            return text

    def run(self, line) -> Result:
        cleaned_line = HTML_ENTITY_RE.sub(self._unescape_fixup, line)
        if line != cleaned_line:
            return Result(status=True, msg=self.debug_str, add=cleaned_line)
        return RESULT_NEXT

    def handle(self, result):
        return Actions(
            stop=True,
            add=[result.add],
            debug_str=result.msg)

class HtmlNamedModule(ModifyModule):
    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='html-named',
            help_str='Replace lines like: &#alpha; Those structures are more like passwords, so be careful to enable '
                     'this option.')

    @staticmethod
    def _unescape_fixup_named(match):
        """
        Replace one matched HTML entity with the character it represents,
        if possible.

        Based on: ftfy.fixes._unescape_fixup
        """
        text = match.group(0)
        if text in HTML_ENTITIES:
            return HTML_ENTITIES[text]
        else:
            return text

    def run(self, line):
        cleaned_line = HTML_ENTITY_RE.sub(self._unescape_fixup_named, line)
        return self.get_result(line, cleaned_line)