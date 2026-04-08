from sys import stderr

global config

# Quick to default logging to stderr instead
def stderr_print(*args, **kwargs):
    #if config['verbose'] is True:
    if True: # TODO pass verbose flag here
        kwargs.setdefault('file', stderr)
        print(*args, **kwargs)

