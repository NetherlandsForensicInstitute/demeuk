### - Add modules -
# Add modules take a line as input, and output either a list of lines or a single line
# which is to be added to the work queue.
# Input is a single str
# Output is either bool result, str out_line, str log OR:
# bool result, list[str] out_lines, str log.
# result should be true if it out_line or out_lines need to be added to the queue
# Q: should we always return a list[str]? Or be nice to future contributors and allow str?
# First case simplifies control flow in main loop, second case simplifies the modules.
# NB: Add modules are not the opposite of remove modules!
from ftfy.fixes import fix_latin_ligatures

from re import split as re_split
from string import punctuation as string_punctuation

global_store_punctuation = string_punctuation
def set_punctuation(punc):
    global global_store_punctuation
    global_store_punctuation = punc


def add_lower(line):
    """Returns if the upper case string is different from the lower case line

    Param:
        line (unicode)

    Returns:
        False if they are the same
        Lowered string if they are not
    """
    line_lower = line.lower()
    if line != line_lower:
        return True, line_lower, f'Add_lower; new line'
    else:
        return False, line, None


def add_first_upper(line):
    """Returns the line with the first letter capitalized and all the others in lowercase.

    Param:
        line (unicode)

    Returns:
        False if they are the same
        Capitalized string if they are not
    """
    line_first_upper = line.capitalize()
    if line != line_first_upper:
        return True, line_first_upper, "Add_first_upper; new line"
    else:
        return False, line, None


def add_title_case(line):
    """Returns title case string where all the first letters are capitals and all others in lowercase.

    Param:
        line (unicode)

    Returns:
        False if they are the same
        Title string if they are not
    """
    line_title_case = line.title()
    if line != line_title_case:
        return True, line_title_case, "Add_title_case; new line"
    else:
        return False, line, None


def add_latin_ligatures(line):
    """Returns the line cleaned of latin ligatures if there are any.

    Param:
        line (unicode)

    Returns:
        False if there are not any latin ligatures
        Corrected line
    """
    cleaned_line = fix_latin_ligatures(line)
    if line != cleaned_line:
        return True, cleaned_line, f'Add_latin_ligatures; new line'
    else:
        return False, line, None


def clean_add_umlaut(line):
    """Returns the line cleaned of incorrect umlauting

    Param:
        line (unicode)

    Returns:
        Corrected line
    """
    cleaned_line = line

    umlaut_dict = {
        'a"': 'ä',
        'i"': 'ï',
        'o"': 'ö',
        'u"': 'ü',
        'e"': 'ë',
        'A"': 'Ä',
        'I"': 'Ï',
        'O"': 'Ö',
        'U"': 'Ü',
        'E"': 'Ë',
    }
    for letter in umlaut_dict.keys():
        cleaned_line = cleaned_line.replace(letter, umlaut_dict.get(letter))

    if line != cleaned_line:
        return True, cleaned_line
    else:
        return False, line

def add_umlaut(line):
    status, result = clean_add_umlaut(line)
    if status:
        return True, result, f'Add_umlaut; new line'
    return False, line, None

def add_split(line, punctuation=(' ', '-', r'\.')):
    """Split the line on the punctuation and return elements longer then 1 char.

    Param:
        line (unicode)

    Returns:
        split line
    """
    for p in punctuation:
        if p in line:
            return [i for i in re_split('|'.join(punctuation), line) if len(i) > 1]
    return False




def add_without_punctuation(line):
    """Returns the line cleaned of punctuation.

    Param:
        line (unicode)

    Returns:
        False if there are not any punctuation
        Corrected line
    """
    cleaned_line = line.translate(str.maketrans('', '', global_store_punctuation))

    if line != cleaned_line:
        return True, cleaned_line, f'Add_without_punctuation; new line'
    else:
        return False, line, None
