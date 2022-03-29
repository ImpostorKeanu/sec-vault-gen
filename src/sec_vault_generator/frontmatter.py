import yaml
import re
from pathlib import Path
from io import TextIOWrapper, StringIO
import logging
from functools import wraps
from copy import deepcopy
from sec_vault_generator.tag import Tag,Tags

log = logging.getLogger('frontmatter')

DELIMITER = '---\n'
WRITE_DELIMITER = f'{DELIMITER}\n'

def checkF(func):
    '''Ensure that the leading f argument is a TextIOWrapper
    and that it's seekable.
    '''

    @wraps(func)
    def wrapper(f, *args, **kwargs):

        if not isinstance(f, TextIOWrapper):
            raise ValueError(
                f'f must be a TextIOWrapper object (file)')
        elif not f.seekable():
            raise ValueError(
                f'f must be seekable')

        return func(f, *args, **kwargs)

    return wrapper

def checkModes(modes):
    '''Ensure that the leading f argument is a TextIOWrapper,
    that it's seeekable, and that it's been opened with the proper
    modes.
    '''

    if not isinstance(modes, list):

        raise ValueError(
            'modes must be a list of string method names for the file '
            'object')

    def outer(func):

        @wraps(func)
        @checkF
        def wrapper(f, *args, **kwargs):

            for mode in modes:

                if not hasattr(f, mode):

                    raise ValueError(
                        f'Invalid file mode supplied: {mode}')

                elif not getattr(f, mode)():

                    raise Exception(
                        f'f {f.name} is not {mode}')

            return func(f, *args, **kwargs)

        return wrapper

    return outer

@checkModes(modes=['readable'])
def hasFrontmatter(f:TextIOWrapper) -> bool:
    '''Check if the leading 4 bytes of the file
    matches a frontmatter signature: ---\n

    Args:
        f: File for reading.

    Returns:
        True when the leading string matches the global DELIMITER.

    Notes:
        - This function resets the stream position to 0.
    '''

    s = f.read(len(DELIMITER))
    f.seek(0)
    return s == DELIMITER

@checkModes(modes=['readable'])
def read(f:TextIOWrapper) -> dict:
    '''Attempt to read Frontmatter from f and return it as a dictionary
    populated with the derived YML content.

    Returns:
        When Frontmatter is observed, a populated dict is returned. An
        empty dictionary is returned otherwise.

    Notes:
        - This function leaves the stream position at the offset where
          the Frontmatter tailer was calculated.
    '''

    fm = {}

    if hasFrontmatter(f):

        # ====================
        # FIND THE FRONTMATTER
        # ====================

        f.seek(len(DELIMITER))
        trailer = None
        while trailer != DELIMITER and trailer != '':
            trailer = f.readline()

        if trailer:

            try:

                # ==========================
                # PARSE THE YAML FRONTMATTER
                # ==========================

                offset = f.tell()
                f.seek(0)
                fm = yaml.load(
                    f.read(offset)[len(DELIMITER):-len(DELIMITER)],
                    Loader=yaml.SafeLoader)

                tags = Tags()
                
                raw = fm.get('tags', '')

                if raw and type(raw) == str:

                    if not ' ' in raw:
                        tags.append(Tag(raw))

                    else:

                        for t in raw.split(' '):
                            if not t: continue
                            tags.append(Tag(t))

                elif raw and type(raw) == list:

                    for t in raw:

                        try:
                            tags.append(Tag(t))
                        except Exception as e:
                            log.debug(
                                f'Failed to add tag to list {t}: {e}')
                            continue

                fm['tags'] = tags

            except Exception as e:

                log.debug(
                    f'Failed to parse frontmatter for {f.name}: {e}'
                )

        else:

            log.debug(
                f'No Frontmatter found in {f.name}'
            )

    return fm

@checkModes(modes=['readable'])
def readAll(f:TextIOWrapper) -> (dict, str,):
    '''Attempt to read frontmatter from f and return the remainaing
    content as a string.

    Args:
        f: File for reading.

    Returns:
        A tuple: (frontmatter_dict, str_content,)

    Notes:
        - This function leaves the stream position at the offset where
          the Frontmatter trailer was calculated.
    '''

    return read(f), f.read().strip()

@checkModes(modes=['writable'])
def write(f:TextIOWrapper, fm:dict=None, content:str=None):
    '''Write YAML frontmatter to a file on disk along with content.

    Args:
        f: Writable file.
        fm: Dictionary of content to be written as Frontmatter.
        content: Content that will be written to disk.
    '''


    fm = fm if fm else {}
    content = content if content else ''

    if 'tags' in fm:

        fm = deepcopy(fm)
        tags = fm.get('tags')
        if isinstance(tags, (list, Tags,)):
            fm['tags'] = [str(t) for t in fm['tags']]

    if fm:

        try:
    
            f.write(DELIMITER)
            yaml.dump(fm, f, Dumper=yaml.SafeDumper)
            f.write(WRITE_DELIMITER)
    
        except Exception as e:
    
            log.debug(f'Failed to write YML frontmatter for {f.name}: {e}')
            f.seek(0)
            f.truncate()

    if content:

        f.write(content)
