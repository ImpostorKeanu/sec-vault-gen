{%- import 'network_scan/macros.template' as macros %}
# Nessus Plugin > `{{ plugin.get('plugin_name') }}`

## Description

{{ plugin.get('description') }}

## Solution

{{ plugin.get('solution') }}

## See Also

{{ macros.bulletList(plugin.get('see_also',[])) }}

{{ macros.affectedSection(ipv4_addresses,
    ipv6_addresses,
    ipv4_sockets,
    ipv6_sockets,
    ipv4_urls,
    ipv6_urls,
    hostnames,
    hostname_sockets,
    hostname_urls,
    ports,
    instances) }}
