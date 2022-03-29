{%- import 'network_scan/macros.template' as macros %}
# {{ protocol }} Port Link(s) > `{{ host }}`

{{ macros.bulletList(links) }}
