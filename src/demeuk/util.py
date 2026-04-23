from sys import stderr


log_verbose = False


def set_verbose():
    global log_verbose
    log_verbose = True


def unset_verbose():
    global log_verbose
    log_verbose = False


# Log to stderr
def stderr_print(*args, **kwargs):
    if log_verbose:
        kwargs.setdefault('file', stderr)
        print(*args, **kwargs)
