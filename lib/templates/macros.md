{% macro bulletList(values, prefix='-') %}
    {%- if caller is defined %}
{# {{ caller() }} #}
    {%- endif %}
    {%- for v in values %}
{{ prefix }} {{ v }}
    {%- endfor %}
{%- endmacro %}

{% macro ifSectionBullets(values, heading) %}
    {%- if values is defined and values %}

# {{ heading }}

        {%- call bulletList(values) %}
{{ bulletList(values) }}
        {%- endcall %}
    {%- endif %}
{%- endmacro %}

{% macro footnoteLinks(values) %}
{%- if values %}
{%- for v in values %}
{{ v }}
{%- endfor %}
{%- endif %}
{%- endmacro %}
