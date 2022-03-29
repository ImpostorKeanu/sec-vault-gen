import yaml
from sec_vault_generator.globals import *
from io import StringIO
from git import Repo
from logging import getLogger
import re

log = getLogger('sec_vault_generator.shortcuts')

RE_SLASH = re.compile('(\\\|/|\.{2,}|:)+')
RE_NON_WORD = re.compile('\W+')
RE_PIPE = re.compile('\|')
RE_TAG_VALID_TOKENS = re.compile('(-|_)+')
RE_TAG_TRAILERS = re.compile('(-|_|/)+$')

WIKILINK = '[[{target}|{text}]]'

def wikilink(target:str, text:str, suffix:str=None) -> str:
    '''Return a Wikilink.

    Returns:
        Obsidian wikilink.

    Notes:
        - Pipes are escaped in both link and text to avoid
          conflicts with Obsidian's link renaming capability.
    '''

    suffix = suffix if suffix else ''

    return WIKILINK.format(
        target=pipeEscape(target),
        text=pipeEscape(text)) + suffix

def pipeEscape(s:str):

    return RE_PIPE.sub('\|', s)

def fsSafeName(s:str) -> str:
    '''Translate a string value to a file name that can
    be safely passed during file operations.

    Args:
        s: String file name.

    Returns:
        Safe file name.
    '''

    return re.sub(RE_SLASH, '_', s)

def sanitizeTag(s:str):
    '''Convert characters that can not be used in an Obsidian
    tag to underscores.
    '''

    return RE_TAG_TRAILERS.sub('',
            RE_NON_WORD.sub(
            lambda m: m.group(0) if m.group(0) in ['_','-'] else '_',
            s))

def suffixGitURLCreds(url:str, username:str, password:str) -> str:
    '''Configure a URL with credentials for authentication
    via Git.

    Args:
        url: Base URL to receive credentials.
        username: Username component of the credentials.
        password: Password value used for authentication.

    Returns:
        str URL.
    '''

    if url.startswith('https://'):
        proto = 'https'
    else:
        proto = 'http'

    return url.replace(
        f'{proto}://',
        f'{proto}://{username}:{password}@')

def dumpYaml(dct:dict, outfile:str):
    '''Dump a dictionary to disk in YML format.

    Args:
        dct: Dictionary to dump.
        outfile: File that will receive the output.
    '''

    log.debug(f'Writing YAML output to {outfile}: dct')

    with open(outfile, 'w+') as outfile:
        yaml.dump(dct, outfile, Dumper=yaml.SafeDumper)

def loadYaml(infile:str):
    '''Load a YML file from disk.

    Args:
        infile: The file to read as YAML.
    '''

    with open(infile) as infile:
        yml = yaml.load(infile, Loader=yaml.SafeLoader)
        log.debug(f'Read YAML input from {infile}: {yml}')
        return yml

def dumpsYaml(dct:dict) -> str:
    '''Return a YML string from dictionary.

    Args:
        dct: The Dictionary to convert to a string.

    Returns:
        YAML formatted string.
    '''

    log.debug(f'Returning dict as YML: {dct}')

    sio = StringIO()
    yaml.dump(dct, sio, Dumper=yaml.SafeDumper)
    sio.seek(0)

    return sio.read()

def cloneRepo(url:str, target:str, branch:str='master') -> Repo:
    '''Clone a repository using GitPython.

    Args:
        url: URL to clone.
        target: Directory where to store the repository.
        branch: The repository branch to clone.

    Returns:
        GitPython Repo object.
    '''

    return Repo.clone_from(url, target)

def cloneKBRepo(url:str=KB_REPO_URL, target:str='bhis_kb',
        branch:str='master') -> Repo:
    '''Clone the BHIS KB repository.

    Args:
        url: URL to clone.
        target: Directory where to store the repository.
        branch: The repository branch to clone.

    Returns:
        GitPython Repo object.
    '''

    return cloneRepo(url, target)
