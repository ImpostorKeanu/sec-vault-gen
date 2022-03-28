{%- import 'network_scan/macros.template' as macros %}
# All Hosts

```
{%- for v in names if v %}
{{ v }}
{%- endfor %}
```

# All Host Links

{{ macros.bulletList(links) }}
