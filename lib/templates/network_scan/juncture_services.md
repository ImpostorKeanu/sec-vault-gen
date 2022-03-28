{%- import 'network_scan/macros.template' as macros %}
#  Services > `{{ service }}`
{% for host, values in links.items() %}
## `{{ host }}`

{{ macros.bulletList(values) }}
{%- endfor %}
