from . import filters
from jinja2 import Environment, PackageLoader, select_autoescape
environment = Environment(
    loader=PackageLoader('sec_vault_generator'),
    autoescape=select_autoescape()
)

environment.filters['noneNull'] = filters.noneNull
