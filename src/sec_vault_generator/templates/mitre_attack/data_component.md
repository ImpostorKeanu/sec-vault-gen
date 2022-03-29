---
tags: 
  - mitre/attack/data_component
---
{%- import 'macros.md' as macros %}
{% include 'mitre_attack/includes/base.md' %}

{{ macros.ifSectionBullets(data_source_links, "Data Source(s)") }}
{{ macros.ifSectionBullets(tactic_links, "Tactic(s)") }}
{{ macros.ifSectionBullets(technique_links, "Technique(s)") }}
{{ macros.footnoteLinks(footnote_links) }}

