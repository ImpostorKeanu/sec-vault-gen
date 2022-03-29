{%- import 'network_scan/macros.template' as macros %}
# Scripts > `{{ script_name }}`
{% for tsocket,values in links.items() %}
## `{{ tsocket }}`

{{ macros.bulletList(values) }}
{%- endfor %}
