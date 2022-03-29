from argparse import (ArgumentParser as AP,
    _HelpAction as HA,
    BooleanOptionalAction)
from sec_vault_generator.globals import *
import inspect
from functools import wraps

def genParentArg(*args, **kwargs):

    parser = AP(add_help=False)
    parser.add_argument(*args, **kwargs)
    return parser

def genArgGroup(mutually_exclusive=False, mutually_required=False,
        *parents, **kwargs):

    # ===========================================
    # DO NOT USE THIS FUNCTION! IT DOES NOT WORK!
    # ===========================================

    parser = AP(add_help=False)
    group = parser.add_argument_group(*args, **kwargs)
    if mutually_exclusive:
        target = parser.add_mutually_exclusive_group(mutually_required)
    else:
        target = group

    for parent in parents:
        for action in parent._actions:
            if type(action) is not HA:
                tartget._actions.append(action)

    return parser

# =================
# GENERIC ARGUMENTS
# =================

def argument(f):

    @wraps(f)
    def wrapper(name_or_flags=None, **kwargs):

        if name_or_flags:
            kwargs['name_or_flags'] = name_or_flags

        spec = inspect.getfullargspec(f)
        defaults = {
            spec.args[ind]:spec.defaults[ind]
            for ind in range(0,len(spec.args))}

        defaults = defaults | kwargs

        return genParentArg(*defaults.get('name_or_flags'), **{
                k:v for k,v in defaults.items()
                if not k.startswith('__') and
                k != 'name_or_flags'})

    return wrapper

@argument
def outputDirectory(name_or_flags=('--output-directory',),
        required=True,
        help='Directory to receive output. '
            'Required: %(required)s; Default: %(default)s'):
    pass

@argument
def cleanUp(name_or_flags=('--clean-up',),
        action=BooleanOptionalAction,
        default=True,
        help='Clean up files and directories after execcution.'):
    pass

@argument
def attackDirectory(name_or_flags=('--attack-directory',),
        required=True,
        help='Absolute path to where MITRE ATT&CK has been deployed in a '
            'vault.'):
    pass

@argument
def inputFiles(name_or_flags=('--input-files', '-ifs'),
        nargs='+',
        required=True,
        help='Input files to process.'):
    pass
