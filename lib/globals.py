import logging
from pathlib import Path
import re

ART = ARGPARSE_REQUIRED_TEMP = \
    'Required: %(required)s; Default: %(default)s'

GITLAB_USERNAME = 'kb-utils'
KB_REPO_NAME = 'kb'

# ====
# URLS
# ====

GITLAB_FQDN = 'git.nopsled.me'
GITLAB_SSH_URL = 'git@{}'.format(GITLAB_FQDN)

GITLAB_HTTPS_URL = 'https://{}'.format(GITLAB_FQDN)
GITLAB_API_URL = '{}/api/v4'.format(GITLAB_HTTPS_URL)

KB_REPO_PATH = '/bhis/{}'.format(KB_REPO_NAME)
KB_REPO_URL = '{}{}'.format(
    GITLAB_HTTPS_URL,
    KB_REPO_PATH)

# ===================
# REGULAR EXPRESSIONS
# ===================

PAT_FILE_PATH_CHARS = re.compile('\.|\/')

# =======
# LOGGING
# =======

LOG_LEVEL = logging.INFO
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s' 

# ================
# FILESYSTEM PATHS
# ================

KB_DIR = Path('bhis_kb')

# Path to the directory where supporting data is being stored
DATA_PATH = Path(__file__).absolute().parent.parent / 'data'

# YML file contining a list of repository URLs
KB_TOOL_METADATA_YML = Path('Content/Automation/Data/tooling_repos.md')

# Directory where volatile content is stored.
VOLATILE_DIR = KB_DIR / 'Volatile'

# From the volatile directory, where the tooling file 
# is stored.
TOOLING_DIR = VOLATILE_DIR / 'Tooling'
TOOLING_RECORDS_DIR = TOOLING_DIR / 'records'
DATAVIEW_MD = TOOLING_DIR / 'tooling.md'
