{%- import 'network_scan/macros.template' as macros %}
# Host > `{{ ip }}`

| Detail        | Value |
| ------------- | ----- |
| Status        | `{{ host['status']        }}` |
| Status Reason | `{{ host['status_reason'] }}` |
| IPv4 Address  | `{{ host.get('ipv4_address', None)|noneNull }}` |
| IPv6 Address  | `{{ host.get('ipv6_address', None)|noneNull }}` |
| MAC Address   | `{{ host.get('mac_address', None)|noneNull }}` |

# Ports
{% for protocol, linkset in ports.items() if linkset %}
## {{ protocol|upper }}

{% for number, link in linkset.items() -%}
- {{ link }}
{% endfor %}
{%- endfor %}
{% if vuln_links %}
# Vulnerabilities
{{ macros.dictBulletList(vuln_links) }}
{%- endif %}

