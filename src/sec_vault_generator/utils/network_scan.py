from sec_vault_generator.util import Util
from sec_vault_generator.exceptions import *
from sec_vault_generator import args
from sec_vault_generator.globals import *
from sec_vault_generator import shortcuts as sc
from sec_vault_generator.jinja import environment as jenv
from sec_vault_generator import frontmatter as FM
from sec_vault_generator.tag import Tag
from argparse import ArgumentParser, BooleanOptionalAction
from logging import getLogger
from pathlib import Path
from shutil import rmtree
from sys import exit
import re
import json
import shutil
import yaml

from IPython import embed
import pdb

from parsuite.parsers.nessus import parse_nessus
from parsuite.parsers.nmap import parse_nmap
from parsuite.helpers import fingerprint_xml
from parsuite.abstractions.xml import (
    nessus as XMLNessus,
    nmap as XMLNmap)
from parsuite.abstractions.xml.generic import network_host as XMLGen
import lxml.etree as ET

from collections import namedtuple

class SevDict(dict):

    def __init__(self, none:list=None, info:list=None, low:list=None,
            medium:list=None, high:list=None, critical:list=None,
            initializer=list):

        return super().__init__(
            none=none if none else initializer(),
            info=info if info else initializer(),
            low=low if low else initializer(),
            medium=medium if medium else initializer(),
            high=high if high else initializer(),
            critical=critical if critical else initializer())

# ====================
# FILESYSTEM TEMPLATES
# ====================

FSYSTEM = FILESYSTEM = \
yaml.load('''
Hostnames: dir
Hosts: dir
Junctures:
  Nessus:
    Plugins: dir
    Severities: dir
  Nmap:
    Scripts: dir
  Ports: dir
  All Hostnames.md: file
  All Hosts.md: file
Services: dir
Info.md: file
''', Loader=yaml.SafeLoader)

HOST_FS = \
yaml.load('''
Nessus Vulnerabilities: dir
Ports: dir
Junctures:
  Hostnames.md: file
  Services.md: file
''', Loader=yaml.SafeLoader)

# ===================
# TEMPLATE REFERENCES
# ===================

TEMPLATE_HOST = \
    jenv.get_template('network_scan/host.md')
TEMPLATE_NES_VULN = \
    jenv.get_template('network_scan/nessus_vulnerability.md')
TEMPLATE_NES_PLUGIN = \
    jenv.get_template('network_scan/nessus_plugin.md')
TEMPLATE_PORT = \
    jenv.get_template('network_scan/port.md')
TEMPLATE_HOSTNAME = \
    jenv.get_template('network_scan/hostname.md')
TEMPLATE_JUNCT_NES_SEVERITIES = \
    jenv.get_template('network_scan/juncture_severities.md')
TEMPLATE_JUNCT_NMAP_SCRIPTS = \
    jenv.get_template('network_scan/juncture_scripts.md')
TEMPLATE_JUNCT_SERVICES = \
    jenv.get_template('network_scan/juncture_services.md')
TEMPLATE_JUNCT_HOST_SERVICES = \
    jenv.get_template('network_scan/juncture_host_services.md')
TEMPLATE_JUNCT_HOST_HOSTNAMES = \
    jenv.get_template('network_scan/juncture_host_hostnames.md')
TEMPLATE_JUNCT_ALL_HOSTNAMES = \
    jenv.get_template('network_scan/juncture_all_hostnames.md')
TEMPLATE_JUNCT_ALL_HOSTS = \
    jenv.get_template('network_scan/juncture_all_hosts.md')
TEMPLATE_JUNCT_HOST_PORTS = \
    jenv.get_template('network_scan/juncture_host_ports.md')

# ====================
# ADDITIONAL VARIABLES
# ====================

PATHS = []

REPORT_ITEM_AFFECTED_ATTRS = \
    ['ipv4_address', 'ipv6_address', 'ipv4_socket', 'ipv6_socket',
     'ipv4_url', 'ipv6_url', 'hostnames', 'hostname_sockets',
     'hostname_urls']

COMMON_PROTOCOLS = ['tcp', 'udp', 'sctp', 'ip']

def dictDropNone(dct:dict) -> None:
    '''Iterate over dct and delete any members that are
    empty or None.
    '''

    keys = list(dct.keys())

    for k in keys:

        v = dct[k]

        if v is None:
            del(dct[k])
        elif hasattr(v, 'len') and len(v) == 0:
            del(dct[k])
        elif isinstance(v, dict):
            dictDropNone(v)

        elif isinstance(v, list):

            for ind in range(0, len(v)):
                iv = v[ind]
                if iv is None:
                    del(v[ind])
                elif hasattr(v, 'len') and len(v) == 0:
                    del(v[ind])
                elif isinstance(iv, dict):
                    dictDropNone(iv)

def getHostIP(host:XMLGen.Host) -> str:

    # ========================
    # NEGOTIATE THE IP ADDRESS
    # ========================

    if host.ipv4_address:
        return host.ipv4_address
    elif host.ipv6_address:
        return host.ipv6_address_slug
    else:
        Build.log.warning(
            f'Host supplied without an IP: {str(host.__dict__)}')
        return None

def handleReportHost(host:XMLGen.Host, root:Path, fingerprint:str):
    '''
    '''

    ip = getHostIP(host)
    if ip is None:
        return

    # =====================
    # MANAGE THE FILESYSTEM
    # =====================

    path = root / 'Hosts' / ip
    new_host = False

    if not path.exists():
        # Build a new directory for the host

        new_host = True

        Build.log.info(
            f'Creating directory for new host: {ip}')
        path.mkdir(parents=True, exist_ok=True)
        PATHS.append(path)
        buildFS(path, leafs=HOST_FS)

    elif path.exists() and path.is_file():
        # Path points to a file

        Build.log.info(
            f"Path exists, but it's a file > {str(path)}")
        return

    # ======================
    # WRITE HOST FRONTMATTER
    # ======================

    host_file = path / addMd(ip)
    with host_file.open('a+') as hf:
        hf.seek(0)
        fm = FM.read(hf)
        hdict = host.__dict__
        dictDropNone(hdict)
        fm[fingerprint+'_host'] = hdict

        # Add a host tag
        tags = fm.get('tags', list())
        tags.append(Tag('scan_result/host'))
        fm['tags'] = tags

        hf.seek(0)
        hf.truncate()
        FM.write(hf, fm)

    # ================
    # TODO: HANDLE HOSTNAMES
    # ================
    '''
    - Write them all to the host file
      - Be sure to link this to the host's hostname juncture file
    - Save one in the Hostnames directory
    '''

    # ============
    # TODO: HANDLE PORTS
    # ============
    '''
    - Ports from Nmap should be treated as authoritiative since
      they have more service data.
    '''

def resolveVaultRoot(root_dirname:str, path:Path) -> str:
    '''Accept the name of the root output directory and a path and
    then read over each element in the path in reverse until the
    last instance matching root_dirname is found.

    Args:
        root_dirname: Name of the output directory within the
            target vault.
        path: Path to iterate over.

    Returns:
        String path from the output directory to the final
        element.

    Raises:
        Exception when the output directory is not found.

    Notes:
        - This is useful when generating relative links.
    '''

    parts = path.parts
    offset = None

    for n in [rn for rn in range(0, len(parts))][::-1]:
        if root_dirname == parts[n]:
            offset = n

    if offset is None:
        raise Exception('Failed to obtain output root!')

    return '/'.join(parts[offset:])

def addMd(s:str):
    return s+'.md'

def expandHosts(root:Path):
    '''
    '''

    hosts_path     = root / 'Hosts'
    hostnames_path = root / 'Hostnames'
    services_path = root / 'Services'
    nessus_plugins_path = root / 'Junctures' / 'Nessus' / 'Plugins'
    nessus_severities_path = root / 'Junctures' / 'Nessus' / 'Severities'
    nmap_scripts_path = root / 'Junctures' / 'Nmap' / 'Scripts'
    all_hosts_path = root / 'Junctures' / 'All Hosts.md'
    all_hostnames_path = root / 'Junctures' / 'All Hostnames.md'

    all_host_links = dict()
    all_script_port_links = dict()
    all_vuln_links = SevDict(initializer=dict)
    all_port_links = dict()
    all_service_port_links = dict()
    all_hostname_links = dict()

    Build.log.info(f'Expanding hosts > {str(hosts_path)}')
    for host_path in hosts_path.glob('*'):

        host_vuln_links = SevDict()
        host_service_links = dict()
        host_hostname_links = list()

        # =================
        # GET THE HOST FILE
        # =================

        if not host_path.is_dir():
            # Host path is not a directory

            Build.log.info(
                'Skipping non-host directory: {}'
                    .format(str(host_path)))
            continue

        host_file = host_path / addMd(host_path.name)
        host_file_link = sc.wikilink(
            target = resolveVaultRoot(
                root.name,
                host_file),
            text = host_path.name)

        all_host_links[host_path.name] = sc.wikilink(
                target = resolveVaultRoot(
                    root.name,
                    host_file),
                text = host_path.name)

        if not host_file.exists():
            # Host file is missing

            Build.log.info(
                'Host directory exists, but the file is missing: {}'
                    .format(str(host_file)))
            continue

        # =====================
        # BUILD PATH REFERENCES
        # =====================

        dir_host_junctures = host_path / 'Junctures'
        dir_host_ports = host_path / 'Ports'
        dir_host_vulnerabilities = host_path / 'Nessus Vulnerabilities'
        host_hostnames_path = dir_host_junctures / 'Hostnames.md'
    
        # ==============================
        # READ METADATA AND MANAGE FILES
        # ==============================

        Build.log.info(f'Expanding > {str(host_file)}')
        with host_file.open('a+') as hfile:
            hfile.seek(0)
            fm = FM.read(hfile)
            hfile.truncate()

            nmap_host = fm.get('nmap_host', dict())
            nessus_host = fm.get('nessus_host', dict())

            # ================
            # MANAGE HOSTNAMES
            # ================

            hostnames = (
                nmap_host.get('hostnames',[]) +
                nessus_host.get('hostnames', []))

            for hn in hostnames:

                # =========================
                # CAPTURE LINK FOR THE HOST
                # =========================

                hn = hn.lower()

                hn_path = hostnames_path / addMd(hn)

                hn_link = sc.wikilink(
                    target = resolveVaultRoot(
                        root.name,
                        hn_path),
                    text = hn)

                host_hostname_links.append(hn_link)

                # ==============================
                # CAPTURE LINK FOR ALL HOSTNAMES
                # ==============================

                host_link = sc.wikilink(
                    target = resolveVaultRoot(
                        root.name,
                        host_file),
                    text = host_path.name)

                if not hn in all_hostname_links:

                    links = [host_link]

                    all_hostname_links[hn] = dict(
                        value = hn,
                        path = hn_path,
                        links = links,
                        host_links = [hn_link])
                else:

                    all_hostname_links[hn]['links'].append(
                        host_link)

                    all_hostname_links[hn]['host_links'].append(
                        hn_link)

            # ============
            # MANAGE PORTS
            # ============

            port_links = dict()

            for protocol in COMMON_PROTOCOLS:

                port_links[protocol] = dict()

                key = protocol+'_ports'

                nmap_ports = nmap_host.get(key, list())
                nessus_ports = nessus_host.get(key, list())

                # Get a list of all port numbers
                port_numbers = list(set([
                    p['number'] for p in nmap_ports+nessus_ports
                ]))

                # Pull the port from each list
                for port in port_numbers:

                    port_fm = dict(
                        host_ip=host_path.name,
                        nmap_port=dict(),
                        nessus_port=dict(),
                        tags=list())

                    # Join port data in a dictionary and write
                    # metadata
                    for nport in nmap_ports:
                        if nport.get('number') == port:
                            port_fm['nmap_port'] = nport
                            break

                    for nport in nessus_ports:
                        if nport.get('number') == port:
                            port_fm['nessus_port'] = nport
                            break

                    # capture a tag
                    port_fm['tags'].append(
                        f'scan_result/port/{protocol}/{port}')
    
                    nmap_port = port_fm.get('nmap_port', dict())
                    nessus_port = port_fm.get('nessus_port', dict())
    
                    if not nmap_port and not nessus_port:
                        continue

                    # ======================
                    # GET THE PORT'S SERVICE
                    # ======================
    
                    # Attempt to get service details from Nmap
                    service = nmap_port.get('service', {})
                    service_name = service.get('name_slug', '')
    
                    if not service_name:
                        # Attempt to recover the service name from Nessus
    
                        report_items = nessus_port.get('report_items', [])
                        if len(report_items) > 0:
                            service_name = report_items[0].get(
                                'service_name_slug', None)
    
                    else:

                        # ============
                        # SERVICE TAGS
                        # ============
    
                        port_fm['tags'].append(
                            f'scan_result/service/{service_name}')

                    tsocket = (
                        f'{protocol}://{host_path.name}:{port}' +
                        (
                            f' ({service_name.upper()})' if
                            service_name else ''
                        ))

                    # ==============================
                    # CRAFT PATHS/LINKS FOR THE PORT
                    # ==============================

                    name_slug = '{protocol}{service}'.format(
                        protocol=protocol.upper(),
                        service=' ('+service_name.upper()+')')
    
                    # Create the new port file
                    port_file_name = '{port} {name_slug}'.format(
                        port = str(port),
                        name_slug = name_slug)

                    port_file = dir_host_ports / addMd(port_file_name)

                    port_link_target = resolveVaultRoot(root.name,
                        port_file)

                    port_link = sc.wikilink(
                        target = port_link_target,
                        text = port_file_name)

                    port_links[protocol][port] = port_link

                    # =====================
                    # CAPTURE SERVICE LINKS
                    # =====================

                    if service_name:

                        # =================
                        # SERVICE PORT LINK
                        # =================

                        if not service_name in all_service_port_links.keys():

                            all_service_port_links[service_name] = \
                                    {host_path.name:[port_link]}

                        else:

                            sd = all_service_port_links[service_name]

                            if not host_path.name in sd:
                                sd[host_path.name] = []

                            sd[host_path.name].append(port_link)

                        # =================
                        # HOST SERVICE LINK
                        # =================

                        sn = service_name.upper()

                        service_link_target = resolveVaultRoot(root.name,
                            (
                                services_path /
                                addMd(sn)))

                        service_link = sc.wikilink(
                            target = service_link_target,
                            text = sn)

                        host_service_links[sn] = service_link

                    # ============================
                    # WRITE THE VULNERABILITY FILE
                    # ============================

                    port_vuln_links = SevDict()

                    for ri in nessus_port.get('report_items', list()):

                        # =========================
                        # GET EXPLOITABILITY STATUS
                        # =========================

                        exploitable_text = ''
                        exploitable_tag = 'not_exploitable'
                        if ri.get('exploit_available', False):
                            exploitable_text = ' 💀'
                            exploitable_tag = 'exploitable'

                        plugin_name = ri.get('plugin_name')
                        plugin_fname = ri.get('plugin_name_slug') 

                        # =================
                        # BUILD PATHS/LINKS
                        # =================

                        vuln_file = dir_host_vulnerabilities / addMd(
                            plugin_fname + f' - {port_file_name}')

                        junct_link = sc.wikilink(
                            target = resolveVaultRoot(
                                root.name,(
                                    nessus_plugins_path /
                                    addMd(ri.get('plugin_name_slug')))),
                            text = plugin_fname + exploitable_text
                        )

                        severity = ri.get('risk_factor').capitalize()

                        severity_link = sc.wikilink(
                            target = resolveVaultRoot(
                                root.name, (
                                    nessus_severities_path /
                                    addMd(severity))),
                            text = severity)

                        vuln_link_target = resolveVaultRoot(root.name,
                            vuln_file)

                        vuln_link = sc.wikilink(
                                target = vuln_link_target,
                                text = plugin_fname + exploitable_text)

                        risk_factor = ri.get('risk_factor')

                        port_vuln_links[risk_factor].append(
                            vuln_link)

                        host_vuln_links[risk_factor].append(
                            vuln_link)

                        # =====================
                        # ADD TO ALL VULN LINKS
                        # =====================

                        vd = all_vuln_links[risk_factor]
                        if not tsocket in vd:
                            vd[tsocket] = [vuln_link]
                        else:
                            vd[tsocket].append(vuln_link)

                        # ================
                        # MANAGE PORT TAGS
                        # ================

                        ri['tags'] = [
                            'scan_result/nessus/vulnerability/' +
                                exploitable_tag,
                            'scan_result/nessus/risk_factor/' +
                                ri.get("risk_factor")
                        ]

                        # ==================
                        # GET ADDRESS VALUES
                        # ==================

                        ipv4_address = ri.get('ipv4_address')
                        ipv6_address = ri.get('ipv6_address')

                        ipv4_socket = ri.get('ipv4_socket')
                        ipv6_socket = ri.get('ipv6_socket')

                        ipv4_url = ri.get('ipv4_url')
                        ipv6_url = ri.get('ipv6_url')

                        hostname = ri.get('hostname')
                        hostname_socket = ri.get('hostname_socket')
                        hostname_url = ri.get('hostname_url')

                        with vuln_file.open('w+') as vfile:
                            FM.write(vfile, ri)
                            vfile.write(
                                TEMPLATE_NES_VULN.render(
                                    plugin_name = plugin_name,
                                    severity_link = severity_link,
                                    host_link = host_file_link,
                                    ipv4_addresses = [ipv4_address] if \
                                        ipv4_address else None,
                                    ipv6_addresses = [ipv6_address] if \
                                        ipv6_address else None,
                                    ipv4_sockets = [ipv4_socket] if \
                                        ipv4_socket else None,
                                    ipv6_sockets = [ipv6_socket] if \
                                        ipv6_socket else None,
                                    ipv4_urls = [ipv4_url] if \
                                        ipv4_url else None,
                                    ipv6_urls = [ipv6_url] if \
                                        ipv6_url else None,
                                    hostnames = [hostname] if \
                                        hostname else None,
                                    hostname_sockets = [hostname_socket] if \
                                        hostname_socket else None,
                                    hostname_urls = [hostname_url] if \
                                        hostname_url else None,
                                    ports = [port],
                                    protocol = protocol,
                                    output = ri.get('plugin_output'),
                                    juncture_link = junct_link))

                    # ==============================
                    # HANDLE THE PORT'S NMAP SCRIPTS
                    # ==============================

                    nmap_port_scripts = nmap_port.get('scripts', None)

                    if nmap_port_scripts:

                        for script in nmap_port_scripts:

                            slug = script['id_slug']

                            # ==========
                            # PORT LINKS
                            # ==========

                            if not slug in all_script_port_links.keys():
                                all_script_port_links[slug] = {
                                    tsocket:[port_link]}
                            else:
                                if not tsocket in all_script_port_links[slug]:
                                    all_script_port_links[slug][tsocket] = \
                                        [port_link]
                                else:
                                    all_script_port_links[slug][tsocket] \
                                        .append(port_link)

                    # ============================
                    # MANAGE THE PORT'S VULN LINKS
                    # ============================

                    for k in port_vuln_links.keys():
                        port_vuln_links[k] = \
                            sorted(list(set(port_vuln_links[k])))
    
                    # ==========================
                    # WRITE THE HOST'S PORT FILE
                    # ==========================

                    with port_file.open('w+') as pfile:
                        FM.write(pfile, port_fm)
                        pfile.write(
                            TEMPLATE_PORT.render(
                                protocol = protocol,
                                ip_address = host_path.name,
                                port = port,
                                service_name = service_name,
                                scripts = nmap_port_scripts,
                                vuln_links = (port_vuln_links if 
                                    port_vuln_links else None),
                                # TODO: Update vault links.
                                vault_links = None))

            # ===================
            # WRITE HOST TEMPLATE
            # ===================

            for k in list(host_vuln_links.keys()):

                host_vuln_links[k] = sorted(
                    list(
                        set(
                            list(host_vuln_links[k]))))

            hfile.write(
                TEMPLATE_HOST.render(
                    ip = host_path.name,
                    host=(
                        nmap_host if nmap_host else nessus_host),
                    ports = port_links,
                    vuln_links = {
                        k.capitalize()+' Severity':v for k,v in
                        host_vuln_links.items()}))

            # ===================
            # WRITE HOST SERVICES
            # ===================

            with (dir_host_junctures / 'Services.md').open('w+') as f:

                FM.write(f, dict(tags=['scan_result/juncture/service']))
                f.write(
                    TEMPLATE_JUNCT_HOST_SERVICES.render(
                        links = host_service_links))

            # ====================
            # WRITE HOST HOSTNAMES
            # ====================

            with host_hostnames_path.open('w+') as f:

                FM.write(f, dict(tags=['scan_result/juncture/hostname']))
                f.write(
                    TEMPLATE_JUNCT_HOST_HOSTNAMES.render(
                        links = host_hostname_links))

            # =========================
            # WRITE HOST PORT JUNCTURES
            # =========================

            for protocol, links in port_links.items():


                protocol = protocol.upper()

                keys = sorted(list(set(list(links.keys()))))
                links = [links[k] for k in keys]

                if not links: continue
                with (dir_host_junctures / addMd(
                        protocol+' Ports')).open('w+') as f:
                
                    FM.write(f, dict(tags=['scan_result/juncture/port']))
                    f.write(
                        TEMPLATE_JUNCT_HOST_PORTS.render(
                            host = host_path.name,
                            protocol = protocol,
                            links = list(set(list(links)))))

    # ===============
    # WRITE ALL HOSTS
    # ===============

    with all_hosts_path.open('w+') as f:

        FM.write(f, dict(tags=['scan_result/juncture/hosts']))
        f.write(
            TEMPLATE_JUNCT_ALL_HOSTS.render(
                names = sorted(list(set(list(all_host_links.keys())))),
                links = sorted(list(set(list(all_host_links.values()))))))

    # ===============
    # WRITE HOSTNAMES
    # ===============

    for key in sorted(list(all_hostname_links.keys())):

        values = all_hostname_links[key]

        with values['path'].open('w+') as f:
            FM.write(f, dict(tags = [
                'scan_result/hostname',
                'scan_result/juncture/hostname']))
            f.write(
                TEMPLATE_HOSTNAME.render(
                    hostname = values['value'],
                    links = values['links']))

    with all_hostnames_path.open('w+') as f:

        links = list()
        values = list()
        for hostname, v in all_hostname_links.items():
            links += v['host_links']
            values.append(hostname)

        FM.write(f, dict(tags=[
            'scan_result/juncture/severity',
            'scan_result/juncture/hostname']))
        f.write(
            TEMPLATE_JUNCT_ALL_HOSTNAMES.render(
                links = sorted(list(set(links))),
                values = sorted(list(set(values)))))

    # ========================
    # WRITE SEVERITY JUNCTURES
    # ========================

    for severity, host_links in all_vuln_links.items():

        for k in host_links.keys():
            host_links[k] = sorted(list(set(host_links[k])))

        if not host_links: continue

        severity = severity.capitalize()

        with (nessus_severities_path / addMd(severity)).open('w+') as f:

            FM.write(f, dict(tags=['scan_result/juncture/severity']))

            f.write(
                TEMPLATE_JUNCT_NES_SEVERITIES.render(
                    severity = severity,
                    links = host_links))

    # ======================
    # WRITE SCRIPT JUNCTURES
    # ======================

    for slug, links in all_script_port_links.items():

        with (nmap_scripts_path / addMd(slug)).open('w+') as f:

            FM.write(f, dict(tags=['scan_result/juncture/script']))
            f.write(
                TEMPLATE_JUNCT_NMAP_SCRIPTS.render(
                    script_name = slug,
                    links = links))

    # =======================
    # WRITE SERVICE JUNCTURES
    # =======================

    for service, links in all_service_port_links.items():

        service = service.upper()

        with (services_path / addMd(service)).open('w+') as f:

            FM.write(f, dict(tags=['scan_result/juncture/service']))
            f.write(
                TEMPLATE_JUNCT_SERVICES.render(
                        service = service,
                        links = links))

def handlePlugins(report, root:Path):

    plugins_root = root / 'Junctures' / 'Nessus' / 'Plugins'

    for plugin_id, plugin in report.plugins.items():

        # ========================================
        # COLLECT VALUES INTO REFERENCE CONTAINERS
        # ========================================

        affected_values = dict(
            ipv4_addresses      = list(),
            ipv6_addresses      = list(),
            ipv4_sockets        = list(),
            ipv6_sockets        = list(),
            ipv4_urls           = list(),
            ipv6_urls           = list(),
            hostnames           = list(),
            hostname_sockets    = list(),
            hostname_urls       = list(),
            ports               = list(),
        )

        host_vuln_links = []
        see_also = None

        # Iterate over each host in the report
        for ip, rhost in report.items():

            # Iterate over each port/report item
            for port in rhost.ports:

                for ritem in port.report_items:

                    # Compare plugin IDs
                    if ritem.plugin_id == plugin_id:

                        affected_values['ports'] \
                            .append(ritem.port.number)

                        # Suffix for the vulnerability name
                        # Is reused for the file name and the link text
                        vuln_fname_suffix = \
                            '{port} {protocol} ({service})'.format(
                                port=port.number,
                                protocol=port.protocol.upper(),
                                service=ritem.service_name_slug.upper())

                        # The file name for the host's vulnerability
                        # file
                        host_vuln_fname = addMd(
                            plugin.plugin_name_slug + ' - ' +
                            vuln_fname_suffix)
    
                        # The link text as it will appear in the plugin
                        # file.
                        link_text = f'{getHostIP(rhost)} -  ' + vuln_fname_suffix

                        # The target of the link that will be embedded in
                        # the plugin file.
                        link_target = resolveVaultRoot(
                            root.name, (
                                root / 'Hosts' / getHostIP(rhost) / 
                                'Nessus Vulnerabilities' / host_vuln_fname)
                            )

                        # Capture the compiled link
                        host_vuln_links.append(
                            sc.wikilink(
                                target = link_target,
                                text = link_text))

                        # ======================================
                        # ADD VALUES TO THE REFERENCE CONTAINERS
                        # ======================================

                        for base in REPORT_ITEM_AFFECTED_ATTRS:

                            # find the proper container
                            for vname in affected_values.keys():
                                if vname == base or vname.startswith(base):
                                    var = affected_values[vname]
                                    break

                            ri_value = getattr(ritem, base)

                            if isinstance(ri_value, list) and \
                                    isinstance(var, list):
                                var += ri_value

                            elif isinstance(var, list) and \
                                    ri_value is not None:
                                var.append(ri_value)

        # ===================
        # UNIQUE/ORDER VALUES
        # ===================

        for k in affected_values.keys():
            affected_values[k] = sorted(set(affected_values[k]))
        host_vuln_links = sorted(set(host_vuln_links))

        # ====================
        # GENERATE FRONTMATTER
        # ====================

        fm = plugin.__dict__
        fm.update(affected_values)
        fm['tags'] = [
            #f'scan_result/nessus/risk_factor/{plugin.risk_factor}',
            f'scan_result/nessus/plugin/{plugin_id}']

        # =====================
        # WRITE THE PLUGIN FILE
        # =====================

        plugin_file = plugins_root / addMd(plugin.plugin_name_slug)

        Build.log.info(f'Writing plugin to disk: {str(plugin_file)}')
        with plugin_file.open('w+') as pfile:
            
            # Write the frontmatter
            FM.write(pfile, fm)
            pfile.write(
                TEMPLATE_NES_PLUGIN.render(
                    plugin = fm,
                    instances = host_vuln_links,
                    **affected_values))

def getDirPath(path:str) -> Path:
    '''Given a string path, identify the Path object within
    the FILESYSTEM global variable and return it.

    Args:
        path: String path to identify.

    Returns:
        Path object.
    '''

    if isinstance(path, Path): path = str(path)

    for d in PATHS:
        if path == str(d):
            return d

    return None

def buildFS(root:Path, leafs:dict=FSYSTEM, verbose:bool=False) -> None:
    '''Build the filesystem to contain the output.

    Args:
        root: Path object pointing to where the items will be created.
        leafs: A Dictionary of items to manage.

    Returns:
        None
    '''

    for key, mem in leafs.items():

        # Memeber element
        path = Path(root / key)
        PATHS.append(path)

        created = not path.exists()

        if isinstance(mem, (dict,)):
            # Handle nested directory/file

            path.mkdir(parents=True, exist_ok=True)
            buildFS(path, mem)

        else:
            # Handle a leaf

            if mem == 'dir':
                path.mkdir(parents=True, exist_ok=True)
            elif mem == 'file':
                path.touch(exist_ok=True)

        if verbose and created:
            # Log when a new directory/file was created

            Build.log.info(
                'Created {}: {}'.format(
                    'directory' if path.is_dir() else 'file',
                    str(path)))

class Build(Util):

    log = getLogger('network_scan.build')

    ap = arg_parser = ArgumentParser(
        description='Build the ATT&CK framework.',
        parents=(
            args.outputDirectory(('--vault-directory','-vd',),
                required=True,
                help='Directory to receive output. '+ART),
            args.inputFiles(
                help='Nmap or Nessus XML files to parse. '+ART)),
        add_help=False)

    ap.add_argument('--results-directory', '-sd',
        default='Scan Results',
        help='Appended to --vault-directory; indicates where parsed '
            'output should be stored. '+ART)

    @staticmethod
    def build(vault_directory:str, results_directory:str, input_files:list):

        # =============================
        # PREPARE THE ROOT OF THE VAULT
        # =============================

        vault_root = Path(vault_directory)
        if not vault_root.exists():
            vault_root.mkdir(parents=True, exist_ok=True)

        ROOT_VAULT_DIR = vault_root.name

        dir_results = vault_root / results_directory
        buildFS(dir_results)

        # ============================
        # BEGIN PROCESSING INPUT FILES
        # ============================

        for _file in input_files:

            # Generate a path object
            _file = Path(_file)

            # Ensure the file exists
            if not _file.exists():
                Build.log.warning(
                    f'Input file was not found > {str(_file)}')
                continue

            # =========================
            # CHECK FOR VALID XML FILES
            # =========================
            
            Build.log.info(f'Parsing > {str(_file)}')
            tree = ET.parse(str(_file))
            fprint = fingerprint_xml(tree)

            if not fprint in ['nessus', 'nmap']:
                Build.log.warning(
                    'Unknown XML file type provided > {str(_file)}.')
                continue

            # ====================
            # PROCESS THE XML FILE
            # ====================

            Build.log.info(f'Processing > {str(_file)}')
            report = globals()['parse_'+fprint](tree, True)

            if fprint == 'nessus':
                Build.log.info('Writing plugins to disk')
                handlePlugins(report, dir_results)

            for host in report.values():
                handleReportHost(host, dir_results, fprint)

        expandHosts(dir_results)

    def __call__(self, *args, **kwargs):

        return Build.build(*args, **kwargs)

