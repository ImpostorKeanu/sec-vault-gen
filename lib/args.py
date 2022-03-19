from argparse import (ArgumentParser as AP,
    _HelpAction as HA)
from lib.globals import *

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

import inspect
from functools import wraps

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

# ================
# GITLAB ARGUMENTS
# ================

gitlab_url = genParentArg('--gitlab-url',
    default=GITLAB_HTTPS_URL,
    help='URL to the Kb repository. Default: %(default)s')

gitlab_username = genParentArg('--gitlab-username',
    default=GITLAB_USERNAME,
    help='Username used during authentication to GitLab. '
        f'Default: %(default)s')

gitlab_token = genParentArg('--gitlab-token',
    required=True,
    help='GitLab token for authentication. Required: %(required)s')

# ====================
# KB-RELATED ARGUMENTS
# ====================

kb_path = genParentArg('--kb-path',
    default=KB_DIR,
    help='Local KB directory. Default: %(default)s')

kb_repo_url = genParentArg('--kb-repo-url',
    default=KB_REPO_URL,
    help='Full URL to the KB repository. Default: %(default)s')

kb_repo_branch = genParentArg('--kb-repo-branch',
    default='master',
    help='Repository branch to act on. Default: %(default)s')

kb_repo_name = genParentArg('--kb-repo-name',
    default=KB_REPO_NAME,
    help='Name of the repository. Default: %(default)s')

# =============
# GIT ARGUMENTS
# =============

commit_msg = genParentArg('--commit-msg',
    default='Automated Push',
    help='Commit message. Default: %(default)s')

push_changes = genParentArg('--push-changes',
    action='store_true',
    help='Determines if changes should be pushed. Default: %(default)s')
