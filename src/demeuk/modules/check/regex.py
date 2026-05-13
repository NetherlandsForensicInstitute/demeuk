from re import search

from ..base import *
from .check import CheckModule


# Do we want a generic RegexCheckModule which we can extend with different regexes we choose?
# This would cut back on duplicate even more, but maybe not necessary.

class RegexModule(CheckModule, ParamModule):

    @staticmethod
    def get_help_info():
        return HelpInfoParam(
            option='check-regex',
            help_str='Drop lines that do not match the regex. Option expects a comma-separated list of regexes.'
                     'For example: [a-z]{1,8},[0-9]{1,8}.',
            metavar='<regexes>',
            param_type=str)

    def run(self, line):
        # TODO I think now we cannot have a regex containing a comma
        for regex in self.param.split(','):
            if search(regex, line):
                continue
            else:
                return self.stop
        return self.next


class EmailModule(CheckModule):

    EMAIL_REGEX = '.{1,64}@([a-zA-Z0-9_-]{1,63}\\.){1,3}[a-zA-Z]{2,6}'

    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='check-email',
            help_str='Drop lines containing e-mail addresses.')

    def run(self, line) -> Result:
        if search(self.EMAIL_REGEX, line):
            return self.stop
        return self.next

class MacAddressModule(CheckModule):

    MAC_REGEX = '^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'

    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='check-mac-address',
            help_str='Drop lines containing MAC addresses.')


    def run(self, line) -> Result:
        if search(self.MAC_REGEX, line):
            return self.stop
        return self.next

class UuidModule(CheckModule):

    UUID_REGEX = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='check-uuid',
            help_str='Drop lines containing UUIDs.')


    def run(self, line):
        if search(self.UUID_REGEX, line):
            return self.stop
        return self.next

class HashModule(CheckModule):
    # Official bcrypt hashes have a bit more fixed size, but saw some weird once:

    # $1a$10$demo as example
    HASH_BCRYPT_REGEX = '^\\$2[ayb]\\$[0-9]{1,}\\$[\\w\\.\\/]{4,}$'
    # Crypt hashes can look a lot like passwords. We do two options here
    # $0[$optional salt, max 16]$string of a-zA-Z0-9./ length 7 min till end of line
    # $0$a-zA-Z0-9./ min length 12 to make sure we hit somthing like: a-zA-Z0-9./
    # this will cause string like $0$JAjdna./d to still be included.

    HASH_HEX_REGEX = '^[a-fA-F0-9]+$'

    HASH_CRYPT_REGEX = '^\\$[1356]\\$[\\w\\.\\/]{12,}$'
    HASH_CRYPT_SALT_REGEX = '^\\$[1356]\\$[\\w\\.\\/\\+]{,16}\\$[\\w\\.\\/]{6,}$'
    HASH_PHPBB_REGEX = '^\\$[hH]\\$[\\w\\.\\/]{5,}$'
    HASH_REGEX_LIST = [HASH_BCRYPT_REGEX, HASH_CRYPT_SALT_REGEX, HASH_CRYPT_REGEX, HASH_PHPBB_REGEX]

    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='check-hash',
            help_str='Drop lines which are hashes')

    def run(self, line):
        if len(line) in [32, 40, 64]:
            if search(self.HASH_HEX_REGEX, line):
                return self.stop
        if len(line) > 0:
            if line[0] == '$':
                for hash_regex in self.HASH_REGEX_LIST:
                    if search(hash_regex, line):
                        return self.stop
        return self.next