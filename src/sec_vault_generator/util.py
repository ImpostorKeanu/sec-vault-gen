from argparse import ArgumentParser

class Util:

    arg_parser = None

    @property
    def arg_parser(self):

        _type = type(self)

        if not hasattr(_type, 'arg_parser'):

            raise Exception(
                f'{type(self)} must have an arg_parser attribute '
                'defined')

        arg_parser = getattr(_type, 'arg_parser')

        if not isinstance(arg_parser, ArgumentParser):

            raise ValueError(
                f'{_type}.arg_parser must be of type ArgumentParser')

        return arg_parser

    def __call__(self, *args, **kwargs):

        raise Exception(
            'Child class must implement a __call__ method.')
