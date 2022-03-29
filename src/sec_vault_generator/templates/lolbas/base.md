{% import 'macros.md' as macros -%}
# {{ name }}

{{ description }}
{{- macros.ifSectionBullets(paths, "Path(s)") -}}

{%- if detections %}

# Detection

{%- for k,v in detections.items() %}
- {{ k }}: [v.split()[-1]]({{ v }})
{%- endfor %}
{%- endif %}
{%- for category, commands in commands_by_category.items() %}

# {{ category }} Commands

{%- for command in commands %}

{{ command["Description"] }}

```batch
{{ command["Command"] }}
```

- **Usecase:** {{ command["Usecase"] }}
- **Privileges Required:** {{ command["Privileges"] }}
- **MitreID:** `{{ command["MitreID"] }}`
- **Operating System(s):** {{ command["OperatingSystem"] }}

{% endfor -%}
{% endfor -%}

{{- macros.ifSectionBullets(resources, "Resource(s)") }}
# Acknowledgements

- {{ author }} (Authored, {{ created }})
{%- for ack in acks %}
- {{ ack }}
{%- endfor -%}
