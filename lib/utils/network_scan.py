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

from parsuite.parsers.nessus import parse_nessus
from parsuite.parsers.nmap import parse_nmap
from parsuite.helpers import fingerprint_xml
from parsuite.abstractions.xml import (
    nessus as XMLNessus,
    nmap as XMLNmap)
from parsuite.abstractions.xml.generic import network_host as XMLGen
import lxml.etree as ET

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
  Nmap:
    Scripts: dir
  Ports:
    All TCP Ports: file
    All UDP Ports: file
    All SCTP Ports: file
    All IP Ports: file
  All Hostnames: file
  All Hosts: file
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

PATHS = []

COMMON_PROTOCOLS = ['tcp', 'udp', 'sctp', 'ip']

TEMPLATE_HOST = jenv.get_template('network_scan/host.md')
TEMPLATE_VULN = jenv.get_template('network_scan/nessus_vulnerability.md')

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

def handleReportHost(host:XMLGen.Host, root:Path, fingerprint:str):
    '''
    '''

    # ========================
    # NEGOTIATE THE IP ADDRESS
    # ========================

    if host.ipv4_address:
        ip = host.ipv4_address
    elif host.ipv6_address:
        ip = host.ipv6_address_slug
    else:
        Build.log.warning(
            f'Host supplied without an IP: {str(host.__dict__)}')

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

    host_file = path / (ip+'.md')
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

def resolveVaultRoot(root_dirname:str, path:Path):
    '''
    '''

    parts = path.parts
    offset = None

    for n in [_in for _in in range(0, len(parts))][::-1]:
        if root_dirname == parts[n]:
            offset = n

    if offset is None:
        raise Exception('Failed to obtain vault root!')

    return '/'.join(parts[offset:])

def expandHosts(root:Path):
    '''
    '''

    hosts_path     = root / 'Hosts'
    hostnames_path = root / 'Hostnames'
    hosts = {}

    Build.log.info(f'Expanding hosts > {str(hosts_path)}')
    for host_path in hosts_path.glob('*'):

        # =================
        # GET THE HOST FILE
        # =================

        if not host_path.is_dir():
            # Host path is not a directory

            Build.log.info(
                'Skipping non-host directory: {}'
                    .format(str(host_path)))
            continue

        host_file = host_path / (host_path.name+'.md')

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
        dir_host_vulnerabilities = host_path / 'Nessus Vulnerabilities'
        dir_host_ports = host_path / 'Ports'

        # ================================
        # BUILD GLOBAL JUNCTURE REFERENCES
        # ================================

        junct_nessus_plugins = dict()
        junct_nessus_severities = dict()
        junct_nmap_scripts = dict()
        junct_services = dict()

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
                hn_path = hostnames_path / (hn+'.md')

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
                        f'scan_result/port/{port}/{protocol}')

                    # ==========================
                    # WRITE THE HOST'S PORT FILE
                    # ==========================
    
                    nmap_port = port_fm.get('nmap_port')
                    nessus_port = port_fm.get('nessus_port')
    
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
                                'service_name_slug', '')
    
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

                    port_file = dir_host_ports / (port_file_name+'.md')
    
                    with port_file.open('w+') as pfile:
                        FM.write(pfile, port_fm)

                    port_links[protocol][port] = sc.wikilink(
                        target = resolveVaultRoot(root.name, port_file),
                        text = port_file_name)

                    # ============================
                    # WRITE THE VULNERABILITY FILE
                    # ============================

                    for ri in nessus_port.get('report_items', list()):

                        plugin_name = ri.get('plugin_name')
                        plugin_fname = ri.get('plugin_name_slug') + \
                            (f' - {port_file_name}')

                        vuln_file = dir_host_vulnerabilities / (
                            plugin_fname+'.md')

                        with vuln_file.open('w+') as vfile:
                            FM.write(vfile, ri)
                            vfile.write(
                                TEMPLATE_VULN.render(
                                    plugin_name = plugin_name,
                                    output = ri.get('plugin_output'))

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
                    ports = port_links))

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

            for host in report.values():
                handleReportHost(host, dir_results, fprint)

        expandHosts(dir_results)

    def __call__(self, *args, **kwargs):

        return Build.build(*args, **kwargs)

