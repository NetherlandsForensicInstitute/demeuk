from sys import stderr

log_verbose = False


def set_verbose():
    global log_verbose
    log_verbose = True


def unset_verbose():
    global log_verbose
    log_verbose = False


# Quick to default logging to stderr instead
def stderr_print(*args, **kwargs):
    if log_verbose:
        kwargs.setdefault('file', stderr)
        print(*args, **kwargs)
