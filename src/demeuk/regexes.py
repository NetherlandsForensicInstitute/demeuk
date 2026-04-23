from re import compile as re_compile


# Search from start to finish for the string $HEX[], with block of a-f0-9 with even number
# of hex chars. The first match group is repeated.
HEX_REGEX = re_compile(r'^\$(?:HEX|hex)\[((?:[0-9a-fA-F]{2})+)\]$')
EMAIL_REGEX = '.{1,64}@([a-zA-Z0-9_-]{1,63}\\.){1,3}[a-zA-Z]{2,6}'
HASH_HEX_REGEX = '^[a-fA-F0-9]+$'
MAC_REGEX = '^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
UUID_REGEX = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

# Officiale bcrypt hashes hae a bit more fixed size, but saw some weird once:
# $1a$10$demo as example
HASH_BCRYPT_REGEX = '^\\$2[ayb]\\$[0-9]{1,}\\$[\\w\\.\\/]{4,}$'
# Crypt hashes can look a lot like passwords. We do two options here
# $0[$optional salt, max 16]$string of a-zA-Z0-9./ length 7 min till end of line
# $0$a-zA-Z0-9./ min length 12 to make sure we hit somthing like: a-zA-Z0-9./
# this will cause string like $0$JAjdna./d to still be included.

HASH_CRYPT_REGEX = '^\\$[1356]\\$[\\w\\.\\/]{12,}$'
HASH_CRYPT_SALT_REGEX = '^\\$[1356]\\$[\\w\\.\\/\\+]{,16}\\$[\\w\\.\\/]{6,}$'
HASH_PHPBB_REGEX = '^\\$[hH]\\$[\\w\\.\\/]{5,}$'
HASH_REGEX_LIST = [HASH_BCRYPT_REGEX, HASH_CRYPT_SALT_REGEX, HASH_CRYPT_REGEX, HASH_PHPBB_REGEX]

TRIM_BLOCKS = ('\\\\n', '\\\\r', '\\n', '\\r', '<br>', '<br />')
