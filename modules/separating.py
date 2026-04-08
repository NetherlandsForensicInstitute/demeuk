def clean_cut(line, delimiters, fields):
    """Finds the first delimiter and returns the remaining string either after
    or before the delimiter.

    Params:
        line (unicode)
        delimiters list(unicode)
        fields (unicode)

    Returns:
        line (unicode)
    """
    for delimiter in delimiters:
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
            return True, delimiter.join(line.split(delimiter)[fields])
    else:
        return False, line
