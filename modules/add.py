from ftfy.fixes import fix_latin_ligatures

from re import split as re_split


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
        return line_lower
    else:
        return False


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
        return line_first_upper
    else:
        return False


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
        return line_title_case
    else:
        return False


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
        return cleaned_line
    else:
        return False


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
        return result
    return False

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




def add_without_punctuation(line, punctuation):
    """Returns the line cleaned of punctuation.

    Param:
        line (unicode)

    Returns:
        False if there are not any punctuation
        Corrected line
    """
    cleaned_line = line.translate(str.maketrans('', '', punctuation))

    if line != cleaned_line:
        return cleaned_line
    else:
        return False
