# Validate modules
import sys

from .parser import *
from .util import stderr_print


# Validate input/output of modules (naively).
# TODO write a guide on how to implement new modules correctly

# Check if all the functions take the correct input (str, optional(param))
def validate_input_signature(order, funcs):
    passed = True
    counter = 0
    for func in funcs:
        err_msg = 'validate: invalid input signature: '
        print_err = False
        if isinstance(func, list):
            # in this case, func = [func, arg].
            # the line should always be the first param.
            opt = order[counter][0]  # The option being checked
            t = lookup_params[opt][1]  # type of parameter
            try:
                func[0]("test string", t(func[1]))
            except TypeError:
                # The offending command-line option
                err_msg += 'wrong # of args'
                print_err = True
                passed = False
            except ValueError:
                passed = False
                err_msg += 'incorrect arg type'
                print_err = True
            err_msg += f'\n\texpected 2 arguments (str, {t.__name__}) for function {func[0].__name__} ({opt})!'
        else:
            # Here, we pass nothing. So the function expects a string
            try:
                # Skip checking of fixed pipeline functions.
                # We assume you know what you're doing if you implement one of these.
                if order[counter] not in flags_fixed:
                    func("test string")
            except TypeError:
                err_msg += 'wrong # of args'
                print_err = True
                passed = False
            err_msg += f'\n\texpected 1 argument (str) for function {func.__name__} ({order[counter]})!'
        if print_err:
            stderr_print(err_msg)
        counter += 1
    return passed


# Check if C/M/A/R module return valid number of return arguments
# Check module expects two return args (bool, str)
# M/A/R expect three return args (bool, str, str)
# NB: Add modules may also return (bool, list[str], str).
# At this time the return type is not checked, only the number of values returned.
def validate_output_signature(order, funcs):
    passed = True
    counter = 0

    # New dict concatenation is py3.9+
    if sys.version_info < (3, 9):
        flags_mar = {**flags_modify, **flags_add, **flags_remove}
        params_mar = {**params_modify, **params_add, **params_remove}
    else:
        flags_mar = flags_modify | flags_add | flags_remove
        params_mar = params_modify | params_add | params_remove

    for func in funcs:
        err_msg = 'validate: invalid output signature: '
        print_err = False

        # We only care about the result of the function, so flags and options can be handled in the same way
        try:
            if isinstance(func, list):
                opt = order[counter][0]
                t = lookup_params[opt][1]
                func_name = func[0].__name__
                if opt in params_mar:
                    result, lines, debug, *rest = func[0]("test string", t(func[1]))
                elif opt in params_check:
                    result, debug, *rest = func[0]("test string", t(func[1]))
                else:
                    counter += 1
                    continue
            else:
                opt = order[counter]
                func_name = func.__name__
                if opt in flags_mar:
                    result, lines, debug, *rest = func("test string")
                elif opt in flags_check:
                    result, debug, *rest = func("test string")
                else:
                    counter += 1
                    continue
            # If we get here, no exception was thrown, so not too few return values.
            if len(rest) > 0:
                err_msg += 'too many return values'
                print_err = True
                passed = False
        except (ValueError, TypeError):
            err_msg += 'too few return values'
            print_err = True
            passed = False
        if print_err:
            err_msg += f'\n\texpected (bool, str, str) for function {func_name} ({opt})'
            stderr_print(err_msg)
        counter += 1
    return passed
