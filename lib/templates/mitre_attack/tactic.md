{%- import 'macros.md' as macros %}
{% include 'mitre_attack/includes/base.md' %}

# Techniques

{#{%- for link, sublinks in tech_links.items() %}
- {{ link }}
    {%- for sub in sublinks %}
  - {{ sub }}
    {%- endfor %}
{%- endfor %}#}

| Technique | Sub-Techniques |
| ---       | ---            |
{%- for link, sublinks in tech_links.items() %}
|{{ link }} |{%- for sub in sublinks %}{{ sub }}<br>{%- endfor %}|
{%- endfor -%}
