from lib.util import Util
from lib.exceptions import *
from lib import args
from lib.globals import *
from lib import shortcuts as sc
from lib.jinja import environment as jenv
from lib import frontmatter as FM
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
            medium:list=None, high:list=None, critical:list=None):

        return super().__init__(
            none=none if none else list(),
            info=info if info else list(),
            low=low if low else list(),
            medium=medium if medium else list(),
            high=high if high else list(),
            critical=critical if critical else list())

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
    Severities:
      Critical.md: file
      High.md: file
      Info.md: file
      Low.md: file
      Medium.md: file
      None.md: file
  Nmap:
    Scripts: dir
  Ports:
    All TCP Ports.md: file
    All UDP Ports.md: file
    All SCTP Ports.md: file
    All IP Ports.md: file
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
  TCP Ports.md: file
  UDP Ports.md: file
  SCTP Ports.md: file
  IP Ports.md: file
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
    nessus_plugins_path = root / 'Junctures' / 'Nessus' / 'Plugins'
    nessus_severities_path = root / 'Junctures' / 'Nessus' / 'Severities'
    hosts = {}

    Build.log.info(f'Expanding hosts > {str(hosts_path)}')
    for host_path in hosts_path.glob('*'):

        host_vuln_links = SevDict()

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
                hn = hn.lower()
                hn_path = hostnames_path / addMd(hn)

                with hn_path.open('w+') as hn_file:

                    # Write hostname Frontmatter
                    FM.write(
                        hn_file,
                        dict(
                            tags=['scan_result/hostname']))

                    # TODO: Link back to Hostnames file in the
                    # host's directory
                    # TODO: Write template here

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
    
                        port_fm['tags'].append(
                            f'scan_result/service/{service_name}')

                    name_slug = '{protocol}{service}'.format(
                        protocol=protocol.upper(),
                        service=' ('+service_name.upper()+')')
    
                    # Create the new port file
                    port_file_name = '{port} {name_slug}'.format(
                        port = str(port),
                        name_slug = name_slug)

                    port_file = dir_host_ports / addMd(port_file_name)

                    port_links[protocol][port] = sc.wikilink(
                        target = resolveVaultRoot(root.name, port_file),
                        text = port_file_name)

                    # ============================
                    # WRITE THE VULNERABILITY FILE
                    # ============================

                    port_vuln_links = SevDict()

                    for ri in nessus_port.get('report_items', list()):

                        plugin_name = ri.get('plugin_name')
                        plugin_fname = ri.get('plugin_name_slug') 

                        vuln_file = dir_host_vulnerabilities / addMd(
                            plugin_fname + f' - {port_file_name}')

                        junct_link = sc.wikilink(
                            target = resolveVaultRoot(
                                root.name,(
                                    nessus_plugins_path /
                                    addMd(ri.get('plugin_name_slug')))),
                            text = plugin_fname
                        )

                        ri['tags'] = [
                            'scan_result/nessus/vulnerability',
                            'scan_result/nessus/risk_factor/'+
                                ri.get("risk_factor")]

                        ipv4_address = ri.get('ipv4_address')
                        ipv6_address = ri.get('ipv6_address')

                        ipv4_socket = ri.get('ipv4_socket')
                        ipv6_socket = ri.get('ipv6_socket')

                        ipv4_url = ri.get('ipv4_url')
                        ipv6_url = ri.get('ipv6_url')

                        hostname = ri.get('hostname')
                        hostname_socket = ri.get('hostname_socket')
                        hostname_url = ri.get('hostname_url')

                        severity = ri.get('risk_factor').capitalize()

                        severity_link = sc.wikilink(
                            target = resolveVaultRoot(
                                root.name, (
                                    nessus_severities_path /
                                    addMd(severity))),
                            text = severity)

                        vuln_link = sc.wikilink(
                                target = resolveVaultRoot(
                                    root.name, vuln_file),
                                text = plugin_fname)

                        port_vuln_links[ri.get('risk_factor')].append(
                            vuln_link)

                        host_vuln_links[ri.get('risk_factor')].append(
                            vuln_link)

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
                                scripts = nmap_port.get('scripts', None),
                                vuln_links = (port_vuln_links if 
                                    port_vuln_links else None),
                                # TODO: Update vault links.
                                vault_links = None))

                    # TODO
                    # Link the port back to the proper protocol
                    # juncture within the host's directory
    
                    # TODO
                    # Look for a global service juncture and
                    # write one when necessary
    
                    # TODO
                    '''
                    FINAL STEPS
    
                    - Clean port data from host frontmatter
                    '''

            # ===================
            # WRITE HOST TEMPLATE
            # ===================

            hfile.write(
                TEMPLATE_HOST.render(
                    host=(
                        nmap_host if nmap_host else nessus_host),
                    ports = port_links,
                    vuln_links = {k.capitalize():v for k,v in host_vuln_links.items()}))

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

