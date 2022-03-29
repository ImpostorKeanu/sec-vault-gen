{%- import 'network_scan/macros.template' as macros %}
# Hostname(s)

```
{%- for v in values %}
{{ v }}
{%- endfor %}
```

# Hostname Link(s)

{{ macros.bulletList(links) }}
