---
tags:
  - mitre/attack/data_source
---
{%- import 'macros.md' as macros %}
{% include 'mitre_attack/includes/base.md' %}

{{ macros.ifSectionBullets(data_component_links, "Data Component(s)") }}
{{ macros.ifSectionBullets(tactic_links, "Tactic(s)") }}
{{ macros.ifSectionBullets(technique_links, "Technique(s)") }}
{{ macros.ifSectionBullets(ext_references, "External Reference(s)") }}
{{ macros.footnoteLinks(footnote_links) }}

