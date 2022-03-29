{%- import 'network_scan/macros.template' as macros %}
# {{ severity }} Severity Vulnerabilities
{% for tsocket,values in links.items() %}
## `{{ tsocket }}`

{{ macros.bulletList(values) }}
{%- endfor %}
