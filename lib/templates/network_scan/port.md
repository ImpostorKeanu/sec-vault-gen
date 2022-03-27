{%- import 'network_scan/macros.template' as macros %}
# Port > `{{ protocol }}://{{ ip_address }}:{{ port }}`{% if service_name %} (`{{ service_name|upper }}`){% endif %}
{% if scripts %}
# Scripts

Sections below contain output from Nmap scripts ran against the port.
{% for script in scripts if scripts is sequence and scripts.__len__() > 0 -%}

## {{ script['id'] }}

**Output:**

```
{{ script['output'] }}
```
{% endfor %}
{%- endif %}
{% if vuln_links -%}
# Port Vulnerabilities
{% for severity, links in vuln_links.items() %}
{% if links.__len__() > 0 -%}
## {{ severity|capitalize }} Severity

{{ macros.bulletList(links) }}
{%- endif %}
{% endfor %}
{% endif %}
{% if vault_links and vault_links.__len__() > 0 -%}
# Vault Links

{{ macros.bulletList(vault_links) }}
{%- endif %}
