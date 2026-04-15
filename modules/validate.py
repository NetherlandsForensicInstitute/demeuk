# Validate modules
from modules.parser import params_check, params_modify, lookup_params, clean_hex, flags_add, \
    params_remove, flags_modify, clean_encode, clean_tab, clean_html, params_add, flags_remove, \
    flags_check
from modules.util import stderr_print


# Clean up, repeating structure over these three functions

# Check if all the functions take the correct input
def validate_input_signature(order, funcs):
    passed = True
    counter = 0
    for func in funcs:
        if isinstance(func, list):
            # in this case, func = [func, arg].
            # the line should always be the first param.
            opt = order[counter][0]  # The option being checked
            t = lookup_params[opt][1]  # type of parameter
            try:
                func[0]("test string", t(func[1]))
            except TypeError:
                # The offending command-line option
                stderr_print("=== INVALID INPUT SIGNATURE === wrong # of args ===\n\t" +
                             "expected 2 arguments " +
                             "(str, " + lookup_params[opt][1].__name__ + ") for function " +
                             func[0].__name__ + " (" + order[counter][0] + ")!")
                passed = False
            except ValueError:
                passed = False
                stderr_print("=== INVALID INPUT SIGNATURE === Incorrect arg type ===\n\t" +
                             "expected 2 arguments " +
                             "(str, " + lookup_params[opt][1].__name__ + ") for function " +
                             func[0].__name__ + " (" + order[counter][0] + ")!")
        else:
            # Here, we pass nothing. So the function expects a string
            try:
                # allow clean_encode and clean_tab. as they operate on bytes instead of strings
                # TODO Do we want to give these special status?
                # TODO bad, hardcoded exception.
                if func not in [clean_encode, clean_tab, clean_hex, clean_html]:
                    func("test string")
            except TypeError:
                # wrong amt of args
                stderr_print("=== INVALID INPUT SIGNATURE === Incorrect arg type\n\t" +
                             "expected 1 argument (str) " +
                             "for function " + func.__name__ +
                             " (" + order[counter] + ")!")
                passed = False
        counter += 1
    return passed


def validate_output_check(order, funcs):
    passed = True
    counter = 0
    for func in funcs:
        if isinstance(func, list):
            if order[counter][0] not in params_check:
                counter += 1
                continue
            # func = [fun, arg]
            # Param (with arg)
            opt = order[counter][0]  # The option being checked
            t = lookup_params[opt][1]  # type of parameter

            try:
                result, debug, *rest = func[0]("test string", t(func[1]))
                if len(rest) > 0:
                    # module returns too much
                    stderr_print("=== INVALID OUTPUT SIGNATURE === wrong # of return values ===" +
                                 "\n\texpected (bool,str) for function " +
                                 func[0].__name__ + " (" + opt + ")!")
                    passed = False
            except ValueError, TypeError:
                stderr_print("=== INVALID OUTPUT SIGNATURE === wrong # of return values ===" +
                             "\n\texpected (bool,str) for function " +
                             func[0].__name__ + " (" + opt + ")!")
                passed = False
        else:
            if order[counter] not in flags_check:
                counter += 1
                continue
            # Flag, without argument
            try:
                result, debug, *rest = func("test string")
                if len(rest) > 0:
                    # module returns too much
                    stderr_print("=== INVALID OUTPUT SIGNATURE === wrong # of return values ===" +
                                 "\n\texpected (bool,str) for function " +
                                 func.__name__ + " (" + order[counter] + ")!")
                    passed = False
            except ValueError, TypeError:
                stderr_print("=== INVALID OUTPUT SIGNATURE === wrong # of return values ===" +
                             "\n\texpected (bool,str) for function " +
                             func.__name__ + " (" + order[counter] + ")!")
                passed = False
        counter += 1
    return passed


# Validate output for modify/add/remove modules
def validate_output_signature(order, funcs):
    passed = True
    counter = 0
    for func in funcs:
        if isinstance(func, list):
            if order[counter][0] not in params_modify | params_add | params_remove:
                counter += 1
                continue
            # func = [fun, arg]
            # Param (with arg)
            opt = order[counter][0]  # The option being checked
            t = lookup_params[opt][1]  # type of parameter

            try:
                result, line, debug, *rest = func[0]("test string", t(func[1]))
                if len(rest) > 0:
                    # module returns too much
                    stderr_print("=== INVALID OUTPUT SIGNATURE === wrong # of return values ===" +
                                 "\n\texpected (bool,str,str) for function " +
                                 func[0].__name__ + " (" + opt + ")!")
                    passed = False
            except ValueError, TypeError:
                stderr_print("=== INVALID OUTPUT SIGNATURE === wrong # of return values ===" +
                             "\n\texpected (bool,str,str) for function " +
                             func[0].__name__ + " (" + opt + ")!")
                passed = False
        else:
            if order[counter] not in flags_modify | flags_add | flags_remove:
                counter += 1
                continue
            # Flag, without argument
            try:
                # TODO also here, hardcoded exception.
                if func not in [clean_encode, clean_tab, clean_hex, clean_html]:
                    result, line, debug, *rest = func("test string")
                    if len(rest) > 0:
                        # module returns too much
                        stderr_print(
                            "=== INVALID OUTPUT SIGNATURE === wrong # of return values ===" +
                            "\n\texpected (bool,str,str) for function " +
                            func.__name__ + " (" + order[counter] + ")!")
                        passed = False
            except ValueError, TypeError:
                stderr_print("=== INVALID OUTPUT SIGNATURE === wrong # of return values ===" +
                             "\n\texpected (bool,str,str) for function " +
                             func.__name__ + " (" + order[counter] + ")!")
                passed = False
        counter += 1
    return passed

# Check module: (bool result, str debug)
# Modify module: (bool status, str line, str debug)
# Add module: (bool status, str line, str debug)
# Rem module: (bool status, str line, str debug)
