{%- import 'macros.md' as macros %}
{% include 'mitre_attack/includes/base.md' %}
{{ macros.ifSectionBullets(platforms, "Platform(s)") -}}
{{ macros.ifSectionBullets(permissions_required, "Permissions Required") -}}
{{ macros.ifSectionBullets(parent_links, "Parent Technique(s)") -}}
{{ macros.ifSectionBullets(child_links, "Sub-Technique(s)") -}}
{{ macros.ifSectionBullets(tool_links, "Tool(s)") -}}
{{ macros.ifSectionBullets(tactic_links, "Tactic(s)") -}}
{%- if detection is defined and detection %}

# Detection

{{ detection }}
    {%- if detections is defined and detections %}

        {%- for src, components in detections.items() %}

            {%- for comp in components %}

### {{ comp["name"] }}

{{ comp["description"] }}

- *Data Component:* {{ comp["_link"] }}
- *Data Source:* {{ src }}
            {%- endfor %}
        {%- endfor %}
    {%- endif %}

{%- endif %}
{{ macros.ifSectionBullets(ext_references, "External Reference(s)") }}
{{ macros.footnoteLinks(footnote_links) }}
