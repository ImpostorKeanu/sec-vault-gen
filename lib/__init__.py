from .globals import *
from . import shortcuts
from . import tag
from . import frontmatter
from logging import getLogger, basicConfig
basicConfig(
    format=LOG_FORMAT,
    level=LOG_LEVEL)
