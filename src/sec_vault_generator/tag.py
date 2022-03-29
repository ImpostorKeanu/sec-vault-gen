import re
import logging
import sec_vault_generator.shortcuts as sc

log = logging.getLogger('tag')

class Base:
    '''Provide a base __repr__ method.
    '''

    def __repr__(self) -> str:

        return ('<{type} id={id} value="{value}" '
            'initial="{initial}">').format(
                type=type(self).__name__,
                id=id(self),
                value=self.value,
                initial=self.initial)

class Tag(Base):

    def __init__(self, initial:(list,str)):
        '''Initialize a new Tag.

        Args:
            initial: A str or a list[str].
        '''

        if not isinstance(initial, (str,list,)):

            raise ValueError(
                'Tag initial value must be a str or a list of str, '
                f'got {type(initial)}')

        elif len(initial) < 1:

            raise ValueError(
                f'initial must have a length greater than 0.')

        if isinstance(initial, list):

            # =================================
            # CONVERT LIST INITIALS TO A STRING
            # =================================

            for v in initial:

                if not isinstance(v, str):

                    raise ValueError(
                        'initial list memeber must be a str, '
                        f'got: {type(v)}')

            initial = '/'.join(initial)

        # Save the initial tag
        self.initial = initial

        # Split the tag into parts
        self.parts = [Part(v) for v in self.initial[
            0 if initial[0] != '#' else 1:].split('/')]

    @property
    def value(self) -> str:
        '''Return the assembled tag.
        '''

        return self.assemble()

    def assemble(self) -> str:
        '''Assemble the parts and return a string tag.
        '''

        return sc.RE_TAG_TRAILERS.sub('',
            '/'.join([str(v) for v in self.parts]))

    def searchParts(self, v:str) -> bool:
        '''Compare v to each part of the tag and return True
        should a match occur.
        '''

        part = Part(v)

        return True in [part == p for p in self.parts]

    def endswith(self, v:str) -> bool:

        part = Part(v)

        return True in [p.value.endswith(part.value) for p in self.parts]

    def startswith(self,v:str) -> bool:

        part = Part(v)

        return True in [p.value.startswith(part.value) for p in self.parts]

    def __str__(self) -> str:
        '''Return the string tag.
        '''

        return self.value

    def __eq__(self, v:str) -> bool:
        '''Compare v to the following instance variables and
        return True should a match occur:
            - id(v) == id(Tag)
            - Tag.initial
            - Tag.value
        '''

        return id(self) == v or \
            v == self.initial or \
            v == self.value
    
class Part(Base):

    def __init__(self, initial:str):
        '''Initialize a tag part.

        Args:
            initial: String tag part
        '''

        if not isinstance(initial, str):

            raise ValueError(
                'Part values require an initial str, '
                f'got: {type(initial)}')

        self.initial = initial
        self.value = sc.sanitizeTag(initial)

    def __str__(self) -> str:
        '''Return the part value as a string.
        '''

        return self.value

    def regex(self, pattern, re_flags=None):

        try:

            if isinstance(pattern, str):
                pattern = re.compile(pattern, re_flags=flags)

        except Exception as e:

            log.info(f'Failed to compile regex pattern: {pattern}')
            raise e

        return pattern.match(self.value) or pattern.match(self.initial)

    def __eq__(self, v:str):

        return self.initial == v or \
                self.value == v or \
                id(self) == id(v)

Part.__eq__.__doc__ = Tag.__eq__.__doc__

from functools import wraps
def uniqueTags(func):

    @wraps(func)
    def wrapper(*args, **kwargs):

        old = func(*args, **kwargs)
        tags = Tags()
        for tag in old:
            if not tag in tags:
                tags.append(tag)

        return tags

    return wrapper

class Tags(list):

    def append(self, tag:Tag):
        '''Append a Tag instance to the list.
        '''

        if not isinstance(tag, Tag):
            raise ValueError(
                'Tags can receive only Tag objects')

        if not tag in self:
            super().append(tag)

    def searchParts(self, v):
        '''Search through each Tag for a match on v.

        Returns:
            List[Tag]
        '''

        return Tags([t for t in self if t == v or t.searchParts(v)])

    @uniqueTags
    def endswith(self, v):

        return Tags([t for t in self if t.endswith(v)])

    @uniqueTags
    def startswith(self, v):

        return Tags([t for t in self if t.startswith(v)])

    @uniqueTags
    def regex(self, pattern, re_flags):

        return Tags([t for t in self if t.regex(pattern, re_flags)])
