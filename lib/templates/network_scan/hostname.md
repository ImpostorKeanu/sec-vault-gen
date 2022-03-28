{%- import 'network_scan/macros.template' as macros %}
# Hostname > `{{ hostname }}`

## Host Link(s)

{{ macros.bulletList(links) }}
