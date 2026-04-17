# Validate modules
from modules.parser import params_check, params_modify, lookup_params, clean_hex, flags_add, \
    params_remove, flags_modify, clean_encode, clean_tab, clean_html, params_add, flags_remove, \
    flags_check, flags_fixed
from modules.util import stderr_print

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
                # allow clean_encode and clean_tab. as they operate on bytes instead of strings
                # TODO Do we want to give these special status?
                # TODO bad, hardcoded exception.
                if func not in [clean_encode, clean_tab, clean_hex, clean_html]:
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


# Check if check module return valid output (bool, str)
def validate_output_check(order, funcs):
    passed = True
    counter = 0
    for func in funcs:
        err_msg = 'validate: invalid output signature: '
        print_err = False


        # We only care about the result of the function, so flags and options can be handled in the same way
        try:
            if isinstance(func, list):
                if order[counter][0] not in params_check:
                    counter += 1
                    continue
                opt = order[counter][0]
                t = lookup_params[opt][1]
                func_name = func[0].__name__
                result, debug, *rest = func[0]("test string", t(func[1]))
            else:
                if order[counter] not in flags_check:
                    counter += 1
                    continue
                opt = order[counter]
                func_name = func.__name__
                result, debug, *rest = func("test string")
            # If we get here, no exception was thrown, so not too few return values.
            if len(rest) > 0:
                err_msg += 'too many return values'
                print_err = True
                passed = False
        except ValueError, TypeError:
            err_msg += 'too few return values'
            print_err = True
            passed = False
        if print_err:
            err_msg += f'\n\texpected (bool, str) for function {func_name} ({opt})'
            stderr_print(err_msg)
        counter += 1
    return passed


# Check if mod/add/rem module return valid output (bool, str, str) or (bool, list[str] str)
# This is the same as validate_output_check, except for the two lines where the module is actually run.
def validate_output_signature(order, funcs):
    passed = True
    counter = 0
    for func in funcs:
        err_msg = 'validate: invalid output signature: '
        print_err = False

        try:
            if isinstance(func, list):
                if order[counter][0] not in params_modify | params_add | params_remove:
                    counter += 1
                    continue
                opt = order[counter][0]
                t = lookup_params[opt][1]
                func_name = func[0].__name__
                # This line
                result, lines, debug, *rest = func[0]("test string", t(func[1]))
            else:
                if order[counter] not in flags_modify | flags_add | flags_remove:
                    counter += 1
                    continue
                opt = order[counter]
                func_name = func.__name__
                # and this line
                result, lines, debug, *rest = func("test string")
            if len(rest) > 0:
                err_msg += 'too many return values'
                print_err = True
                passed = False
        except ValueError, TypeError:
            err_msg += 'too few return values'
            print_err = True
            passed = False
        if print_err:
            err_msg += f'\n\texpected (bool, str, str) for function {func_name} ({opt})'
            stderr_print(err_msg)
        counter += 1
    return passed
