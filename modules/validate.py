# Validate modules
from modules.parser import lookup_params
from modules.util import stderr_print


# Check if all the functions take the correct input
def validate_input_signature(order, funcs):
    passed = True
    counter = 0
    for func in funcs:
        if isinstance(func, list):
            # in this case, func = [func, arg].
            # the line should always be the first param.
            opt = order[counter][0]     # The option being checked
            t = lookup_params[opt][1]   # type of parameter
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
                # TODO change msg
                stderr_print("=== INVALID MODULE SIGNATURE === Incorrect arg type ===\n\t" +
                             "expected 2 arguments " +
                             "(str, " + lookup_params[opt][1].__name__ + ") for function " +
                             func[0].__name__ + " (" + order[counter][0] + ")!")
        else:
            # Here, we pass nothing. So the function expects a string
            try:
                func("test string")
            except TypeError:
                # wrong amt of args
                stderr_print("=== INVALID MODULE SIGNATURE ===\n\texpected 1 argument (str) " +
                             "for function " + func.__name__ +
                             " (" + order[counter] + ")!")
                passed = False
        counter += 1
    return passed

def validate_output_signature(order, funcs):
    passed = True
    # TODO continue