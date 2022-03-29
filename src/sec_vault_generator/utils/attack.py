from sec_vault_generator.util import Util
from sec_vault_generator.exceptions import *
from sec_vault_generator import args
from sec_vault_generator.globals import *
from sec_vault_generator import shortcuts as sc
from sec_vault_generator.jinja import environment as jenv
from sec_vault_generator import frontmatter as FM
from argparse import ArgumentParser, BooleanOptionalAction
from logging import getLogger
from pathlib import Path
from shutil import rmtree
from copy import deepcopy
from sys import exit
import re
import json
import shutil

from IPython import embed

RE_CITATION         = re.compile('\(Citation: (?P<value>.*?)\)', re.I)
RE_ATTACK_JSON_NAME = re.compile(
    '^enterprise-attack-'
    '(?P<ver>[1-9]([0-9]{1,})?\.[0-9]{1,})\.json$', re.I)

data_comp_temp      = jenv.get_template('mitre_attack/data_component.md')
data_src_temp       = jenv.get_template('mitre_attack/data_source.md')
technique_temp      = jenv.get_template('mitre_attack/technique.md')
tactic_temp         = jenv.get_template('mitre_attack/tactic.md')
tool_temp           = jenv.get_template('mitre_attack/tool.md')
malware_temp        = jenv.get_template('mitre_attack/malware.md')
tactic_index_temp   = jenv.get_template('mitre_attack/tactic_index.md')

def initializer(obj, dir_path, file_ext='.md',
        lookup_attrs=None, sanitizer=sc.fsSafeName):

    obj['_tag_name'] = sc.sanitizeTag(obj.get('name', '')).lower()

    # ==================
    # INITIALIZE LOOKUPS
    # ==================

    lookup_attrs = lookup_attrs if lookup_attrs else []

    for a in lookup_attrs:
        obj[a] = Lookup()

    # =================
    # SET COMMON VALUES
    # =================

    obj['_safe_name'] = sanitizer(obj.get('name',''))
    obj['_path'] = dir_path / (obj['_safe_name']+file_ext)
    obj['_link'] = relWikilink(dir_path.name, obj.get('name',''), sanitizer=sanitizer)

    # ============================
    # SET EXTERNAL REFERENCE LINKS
    # ============================

    obj['_external_reference_links'] = []
    obj['_footnote_links'] = []
    ext_refs = obj.get('external_references', [])
    citations = RE_CITATION.findall(obj.get('description', '')) + \
        RE_CITATION.findall(obj.get('x_mitre_detection',''))

    for ind in range(0,len(ext_refs)):
        
        ref = ext_refs[ind]
        ref['_index'] = ind

        source_name = ref.get('source_name')
        ext_id = ref.get('external_id')
        desc = ref.get('description')
        url = ref.get('url')

        obj['_ext_id'] = ext_id if not obj.get('_ext_id') else obj['_ext_id']
        if source_name == 'mitre-attack' and ext_id and url:
            obj['_mitre_url'] = url
            ref['link'] = '[{}]({})'.format(ext_id, url)
        elif desc and url:
            ref['link'] = '[{}]({})'.format(desc, url)
        elif url:
            ref['link'] = url

        # ================
        # HANDLE CITATIONS
        # ================
    
        found = False
        for citation in citations:
    
            ref = ext_refs[ind]

            if citation != ref.get('source_name', '') or not ref.get('link'):
                continue

            if obj['type'] == 'relationship':

                # =============================
                # HANDLE RELATIONSHIP CITATIONS
                # =============================
                '''
                - These are simplified citations since they reside outside
                  of their associated objects, yet individual files for them
                  are not created.
                - Instead of footnotes, we link directly to the source of the
                  link.
                '''

                fn = '[\[{text}\]]({link})'.format(
                    text=citation,
                    link=url)

            else:

                fn = f'[^fn{ref["_index"]}]'
                ref['link'] = f'{fn}: {ref["link"]}'

            # ============================
            # HANDLE DESCRIPTION CITATIONS
            # ============================
    
            obj['description'] = re.sub(
                re.escape('(Citation: '+citation+')'),
                fn, obj['description']
            )

            if obj.get('x_mitre_detection'):

                # ==========================
                # HANDLE DETECTION CITATIONS
                # ==========================

                obj['x_mitre_detection'] = re.sub(
                    re.escape('(Citation: '+citation+')'),
                    fn, obj['x_mitre_detection']
                )

            found = True
            break

        if found and ref.get('link'):
            obj['_footnote_links'].append(ref['link'])
        elif ref.get('link'):
            obj['_external_reference_links'].append(ref['link'])

def relWikilink(dirname, name, sanitizer=sc.fsSafeName, suffix=None):

    suffix = suffix if suffix else ''

    return sc.wikilink(
        target=f'../{dirname}/{sanitizer(name)}',
        text=name) + suffix

class Lookup(dict):

    def reverse(self, value):
        '''Search all values in Lookup and return its associated
        key should it be found, otherwise None.

        Args:
            value: The value to search for.
        '''

        for k,v in self.items():

            if value == v:

                return k

        return None

    def subkey(self, k, v):
        '''Iterate over each value in Lookup and determine if
        the nested Lookup object has k and a matching value (v).
        '''

        for ik, iv in self.items():

            try:

                if not k in iv:
                    continue
    
                elif isinstance(iv[k], (list, set,)) and v in iv[k]:
                    return iv
    
                elif isinstance(iv[k], (dict,)) and v in iv[k].values():
                    return iv
    
                elif iv[k] == v:
                    return iv
            except:
                continue

        return None

def normalizeShortname(v):

    return sc.fsSafeName(' '.join(
        w.capitalize() if not w in ['and'] else w
        for w in v.split('-')))

class Link(Util):

    log = getLogger('attack.link')

    ap = arg_parser = ArgumentParser(
        description='Embed links into ATT&CK framework files.',
        parents=(
            args.attackDirectory(),),
        add_help=False)

    ap.add_argument('--vault-scan-depth',
        default=10, type=int,
        help='Depth to scan for the .obsidian directory that '
          'generally indicates the root of an Obsidian vault.')

    ap._action_groups[1].title = 'arguments'

    @staticmethod
    def link(attack_directory:str, vault_scan_depth:int):

        p_attack_dir = Path(attack_directory)

        if not p_attack_dir.exists():

            Link.log.info(
                f'Attack directory "{p_attack_dir}" does not exist. '
                'Exiting.')
            exit()

        # ==========================
        # FIND THE ROOT OF THE VAULT
        # ==========================

        Link.log.info('Scanning for vault root...')
        p_vault_dir = p_attack_dir / '..' / '.obsidian'
        while vault_scan_depth > 0:

            vault_scan_depth -= 1

            if p_vault_dir.exists() and p_vault_dir.is_dir():
                p_vault_dir = (p_vault_dir / '..').resolve()
                Link.log.info(f'Found vault root: {p_vault_dir}')
                break

            if vault_scan_depth == 0:
                Link.log.info('Failed to find vault root! Exiting.')
                exit()

            p_vault_dir = p_vault_dir / '..' / '.obsidian'

        # ================================
        # GENERATE AN INDEX OF MITRE FILES
        # ================================

        Link.log.info('Extracting metadata from MITRE ATT&CK files...')
        mitre = dict()
        for item in p_attack_dir.glob('**/*.md'):

            with item.open('r+') as infile:
                fm = FM.read(infile)

            if not fm: continue

            mdata = fm.get('mitre_data', dict())

            mitre[item] = dict(
                linker_tags = mdata.get('linker_tags', list()),
                technique_id = (mdata.get('id', '').lower()),
                vault_links = list())

        # =======================
        # PROCESS NON-MITRE FILES
        # =======================

        linker_pref = 'mitre/attack/linker'

        # Number of path parts 
        path_slice = len(p_vault_dir.parts)

        # Signature to know if a file should be skipped
        # We never want to parse MITRE files
        omitter = '[[' + p_attack_dir.name + '/'

        # Begin searching for files that wish to link into
        # MITRE.
        Link.log.info('Processing Non-MITRE ATT&CK files for '
            'tags/technique IDs')
        for item in p_vault_dir.glob('**/*.md'):

            link = "/".join(item.parts[path_slice:])
            name = str(link).replace('.md', '')
            link = f'[[{link}|{name}]]'

            # Skip unrelated files
            if link.startswith(omitter):
                continue

            # Read in frontmatter
            with item.open('r+') as f:
                fm = FM.read(f)

            # Look for linker tags
            tags = fm.get('tags')
            linker_tags = []
            if isinstance(tags, list):

                for tag in tags:

                    if not tag.startswith(linker_pref):
                        continue
                    else:
                        linker_tags.append(tag)

                    # TODO: Scan MITRE linker tags and
                    # append the link.
                
            # Check mitre_data
            tech_ids = list()
            if fm and 'mitre_data' in fm:

                tech_ids = [
                    str(i).lower() for i in
                    fm['mitre_data'].get('technique_ids', list())
                ]

            # =================================
            # ASSOCIATE LINKS TO MITRE ELEMENTS
            # =================================

            for path, mdata in mitre.items():

                for t in linker_tags:

                    if t in mdata['linker_tags'] and \
                            not link in mdata['vault_links']:

                        mdata['vault_links'].append(link)
                        continue

                m_tid = mdata.get('technique_id')

                if m_tid in tech_ids and not \
                        link in mdata['vault_links']:

                    mdata['vault_links'].append(link)
                    continue

        # ================================
        # WRITE VAULT LINKS TO MITRE FILES
        # ================================
        Link.log.info('Writing "Vault Links" section to each MITRE '
            'file')

        header = '\n\n# Vault Links\n'
        for path, mdata in mitre.items():
            if len(mdata['vault_links']) == 0: continue
            with path.open('a+') as mfile:

                # ==============================
                # TRUNCATE AT VAULT LINKS HEADER
                # ==============================

                mfile.seek(0)
                offset = 0
                found = False

                for line in mfile:
                    if found == False:
                        offset += len(line)
                        if line == '# Vault Links\n':
                            found = True

                if found:
                    mfile.seek(offset-len(header))
                    mfile.truncate()

                # ===========
                # WRITE LINKS
                # ===========

                mfile.write(header)
                for link in mdata['vault_links']:
                    mfile.write(f'\n - {link}')

        Link.log.info('Linking complete. MITRE ATT&CK tactic and '
            'technique files should now contain a "Vault Links" '
            'section with links to properly configured files.')

    def __call__(self, *args, **kwargs):

        return Link.link(*args, **kwargs)

class Build(Util):

    log = getLogger('attack.build')

    ap = arg_parser = ArgumentParser(
        description='Build the ATT&CK framework.',
        parents=(
            args.outputDirectory(('--output-directory','-od',),
                required=False,
                default='MITRE Attack',
                help='Directory to receive output. '+ART),
            args.cleanUp(
                help='Determines if the repository should be deleted '
                'after parsing.'),),
        add_help=False)

    ap.add_argument('--attack-repo',
        default='https://github.com/mitre-attack/attack-stix-data',
        help='Repository containing the ATT&CK content. '+ART)

    ap.add_argument('--tactics-directory',
        default='Tactics',
        help='Appended to -od; the directory to store '
            'tactics markdown files. '+ART)

    ap.add_argument('--techniques-directory',
        default='Techniques',
        help='Appended to -od; the directory to store '
            'techniques markdown files. '+ART)

    ap.add_argument('--data-sources-directory',
        default='Data Sources',
        help='Appended to -od; the directory to store '
            'data source markdown files. '+ART)

    ap.add_argument('--data-components-directory',
        default='Data Components',
        help='Appended to -od; the directory to store '
            'data component markdown files. '+ART)

    ap.add_argument('--malwares-directory',
        default='Malwares',
        help='Appended to -od; the directory to store '
            'data source markdown files. '+ART)

    ap.add_argument('--tools-directory',
        default='Tools',
        help='Appended to -od; the directory to store '
            'data component markdown files. '+ART)

    ap._action_groups[1].title = 'arguments'

    @staticmethod
    def build(output_directory:str, attack_repo:str, tactics_directory:str,
            techniques_directory:str, data_sources_directory:str,
            data_components_directory:str, malwares_directory:str,
            tools_directory:str, clean_up:bool):

        # ========================
        # PREPARE FILESYSTEM PATHS
        # ========================

        output_directory = Path(output_directory)
        tactics_directory = output_directory / tactics_directory
        techniques_directory = output_directory / techniques_directory
        data_sources_directory = output_directory / data_sources_directory
        data_components_directory = output_directory / data_components_directory
        malwares_directory = output_directory / malwares_directory
        tools_directory = output_directory / tools_directory
        relationships_directory = output_directory / 'Relationships'

        # =============================
        # PREPARE THE ATTACK REPOSITORY
        # =============================

        if not Path('attack-stix-data').exists():
            Build.log.info('Cloning the ATT&CK repository.')
            repo = sc.cloneRepo(url=attack_repo,
                target='attack-stix-data')
        else:
            Build.log.info('Using cached ATT&CK repository.')

        files = {}

        for f in Path('attack-stix-data/enterprise-attack').glob('*.json'):

            match = RE_ATTACK_JSON_NAME.match(f.name)

            if not match:
                Build.log.info(f'Invalid attack JSON file: {f.name}')
                continue

            files[float(match.groups()[0])] = f

        infile = files[sorted(list(files.keys()))[-1]]

        Build.log.info(f'Negotiated input file: {infile.name}')

        # ==================
        # LOAD THE JSON DATA
        # ==================
        
        # Load the JSON object
        with infile.open() as f:
            try:
                attack = json.load(f)
            except Exception as e:

                # =======================
                # EXIT WHEN PARSING FAILS
                # =======================

                Build.log.info(f'Failed to parse JSON file: {f}. Exiting.')
                exit()

        objects = attack['objects']
        
        # ======================
        # BUILD OUTPUT DIRECTORY
        # ======================
        
        output_directory.mkdir(parents=True, exist_ok=True)
        tactics_directory.mkdir(parents=True, exist_ok=True)
        techniques_directory.mkdir(parents=True, exist_ok=True)
        data_sources_directory.mkdir(parents=True, exist_ok=True)
        data_components_directory.mkdir(parents=True, exist_ok=True)
        malwares_directory.mkdir(parents=True, exist_ok=True)
        tools_directory.mkdir(parents=True, exist_ok=True)
        
        # ===============================================
        # GET ALL RELATIONSHIPS & SOFTWARE (Malware/Tool)
        # ===============================================
        
        tactic_refs = None
        tactics, techniques, relationships, malwares, \
            tools, data_sources, data_components = \
            Lookup(), Lookup(), Lookup(), Lookup(), \
            Lookup(), Lookup(), Lookup()
        
        for obj in objects:
        
            # =========================
            # CAPTURE TACTIC REFERENCES
            # =========================
        
            if tactic_refs is None and obj['type'] == 'x-mitre-matrix':
                tactic_refs = obj['tactic_refs']
                continue
        
            # TODO: Determine what revoked actually means, here
            if 'revoked' in obj and obj['revoked']: continue
        
            try:
                collection, dir_path, lookups = {
                    'x-mitre-tactic': (
                        tactics, tactics_directory, ['_techniques'],),
                    'attack-pattern': (
                        techniques, techniques_directory, [
                            '_data_components',
                            '_data_sources',
                            '_parents',
                            '_children',
                            '_tools',
                            '_tool_relationships',
                            '_malwares',
                            '_malware_relationships'],),
                    'relationship': (
                        relationships, relationships_directory, [],),
                    'malware': (
                        malwares, malwares_directory, [
                            '_techniques'],),
                    'tool': (
                        tools, tools_directory, [
                            '_techniques'],),
                    'x-mitre-data-source': (
                        data_sources, data_sources_directory, [
                            '_techniques',
                            '_tactics',
                            '_data_components'],),
                    'x-mitre-data-component': (
                        data_components, data_components_directory, [
                            '_techniques',
                            '_tactics',
                            '_data_sources'],)} \
                    [obj['type']]
            except:
                continue

            # =====================
            # INITIALIZE THE OBJECT
            # =====================

            initializer(obj, dir_path, lookup_attrs=lookups)
                                    
            collection[obj['id']]=Lookup(obj)

        if not tactic_refs:
            raise Exception('Failed to obtain tactic references')

        # =======================
        # PREPARE ALL THE TACTICS
        # =======================
        
        # Create a lookup dictionary: { tactic_id:tactic_object }
        for _id in tactic_refs:
        
            tactic = tactics.subkey('id', _id)
        
            offset = str(tactic_refs.index(_id)+1)+'. '
        
            # Create a path object for the tactic object
            name = normalizeShortname(tactic['x_mitre_shortname'])
            path = tactics_directory / (
                    offset +
                    sc.fsSafeName(name) +
                    '.md')
        
            tactic['_normalized_name'] = name
            tactic['_path'] = path
            tactic['_link'] = \
                f'[[../{tactics_directory.name}/{offset}{name}|{name}]]'
        
            if not _id in tactics:
                raise ValueError(f'Missing tactic object in objects list: {_id}')
        
        # ========================================================
        # ASSOCIATE ALL SUBTECHNIQUES/DATA SOURCES/DATA COMPONENTS
        # ========================================================
        
        for _id, tech in techniques.items():
        
            tech['_is_subtechnique'] = tech.get('x_mitre_is_subtechnique', False)
        
            for _rid, rel in relationships.items():
        
                if tech['_is_subtechnique']:
        
                    if rel['relationship_type'] != 'subtechnique-of' or \
                            rel['source_ref'] != _id:
                        continue
            
                    parent = techniques[rel['target_ref']]
                    tech['_parents'][rel['target_ref']] = parent
            
                    if not '_children' in parent:
                        parent['_children'] = Lookup()
            
                    parent['_children'][_id] = tech
        
        # ====================================
        # GET ALL TECHNIQUES (attack-patterns)
        # ====================================
        
        for _id, tech in techniques.items():

            # =================================
            # PREPARE LINK FOR THE TACTIC INDEX
            # =================================

            tech['_tactic_tag_names'] = tactic_tag_names = []
            tech['_tag_partials'] = tag_partials = []
            tech['_tactics'] = Lookup()
            safe_name = sc.fsSafeName(tech['name']) + f' ({tech["_ext_id"]})'
            tech['_path'] = techniques_directory / (safe_name+'.md')
            tech['_link'] = sc.wikilink(
                target=f'../{techniques_directory.name}/{safe_name}',
                text=tech["name"])

            # ================================
            # ASSOCIATE TECHNIQUE WITH TACTICS
            # ================================
        
            if not 'kill_chain_phases' in tech.keys():
                continue
        
            for v in tech['kill_chain_phases']:
        
                # Look up the tactic based on normalized name
                tactic = tactics.subkey('_normalized_name', 
                        normalizeShortname(v['phase_name']))

                if not tactic.get('_tag_name') in tactic_tag_names:
                    tactic_tag_names.append(tactic['_tag_name'])

                partial = (tactic['_tag_name'] + '/' + tech['_tag_name'])

                if not partial in tag_partials:
                    tag_partials.append(partial)
        
                # Link the technique into the tactic
                tactic['_techniques'][tech['id']] = tech
        
                # Link the tactic into the technique
                tech['_tactics'][tactic['id']] = tactic
        
        # =================================
        # ASSOCIATE DATA SOURCES/COMPONENTS
        # =================================
        
        for _rid, rel in relationships.items():

            # =========================================================
            # ESTABLISH RELATIONSHIP TYPE AND GET SOURCE/TARGET OBJECTS
            # =========================================================

            rel_type = rel.get('relationship_type', '')

            source_ref = rel.get('source_ref', '')
            target_ref = rel.get('target_ref', '')

            if source_ref.startswith('attack-pattern'):
                scol = techniques
            elif source_ref.startswith('x-mitre-data-component'):
                scol = data_components
            elif source_ref.startswith('malware'):
                scol = malwares
            elif source_ref.startswith('tool'):
                scol = tools
            else:
                continue
        
            if target_ref.startswith('attack-pattern'):
                tcol = techniques
            elif target_ref.startswith('x-mitre-data-component'):
                tcol = data_components
            elif target_ref.startswith('malware'):
                tcol = malwares
            elif target_ref.startswith('tool'):
                tcol = tools
            else:
                continue

            try:
                sval = scol[source_ref]
                tval = tcol[target_ref]
            except KeyError as err:
                Build.log.debug(
                    f'Failed to look up object by key while handling relationship: {err}')
                continue

            # ========================
            # ACT ON THE RELATIONSHIPS
            # ========================
        
            if rel['type'] == 'relationship' and \
                    target_ref.startswith('attack-pattern') and \
                    source_ref.startswith('x-mitre-data-component'):
        
                tech = tval
                comp = sval
                src = data_sources[comp['x_mitre_data_source_ref']]
        
                # Associate the data source with the tech
                tech['_data_sources'][src['id']] = src
                tech['_data_components'][comp['id']] = comp
        
                # Associate the src and comp
                comp['_data_sources'][src['id']] = src
                src['_data_components'][comp['id']] = comp
        
                # Associate the tech with the src and comp
                comp['_techniques'][tech['id']] = tech
                src['_techniques'][tech['id']] = tech
        
                for _id, tactic in tech['_tactics'].items():
                    if not comp['_tactics'].get(_id):
                        comp['_tactics'][_id] = tactic
                    if not src['_tactics'].get(_id):
                        src['_tactics'][_id] = tactic

            elif rel_type == 'uses' and \
                    source_ref.startswith('malware') and \
                    target_ref.startswith('attack-pattern'):

                # ======================
                # MALWARE USES TECHNIQUE
                # ======================

                tech = tval
                mal = sval

                if not tech['id'] in mal['_techniques']:
                    mal['_techniques'][tech['id']] = tech

                if not mal['id'] in tech['_malwares']:
                    tech['_malwares'][mal['id']] = mal

                if not rel['id'] in tech['_malware_relationships']:
                    tech['_malware_relationships'][rel['id']] = rel

            elif rel_type == 'uses' and \
                    source_ref.startswith('tool') and \
                    target_ref.startswith('attack-pattern'):

                # ===================
                # TOOL USES TECHNIQUE
                # ===================

                tech = tval
                tool = sval
        
                if not tech['id'] in tool['_techniques']:
                    tool['_techniques'][tech['id']] = tech

                if not tool['id'] in tech['_malwares']:
                    tech['_tools'][tool['id']] = tool

                if not rel['id'] in tech['_tool_relationships']:
                    tech['_tool_relationships'][rel['id']] = rel

        # ==================
        # WRITE OUTPUT FILES
        # ==================

        Build.log.info('Writing output files')

        # TACTICS
        for key, tactic in tactics.items():

            with tactic['_path'].open('w+') as outfile:

                # ===========================================
                # AGGREGATE TECHNIQUE LINKS INTO A DICITONARY
                # ===========================================

                tags = ['mitre/attack/tactic']

                mitre_data = dict(
                    linker_tags=[f'mitre/attack/linker/{tactic["_tag_name"]}'])

                FM.write(outfile, dict(tags=tags, mitre_data=mitre_data))

                links = {}
                for _id, tech in tactic['_techniques'].items():

                    if not tech['_is_subtechnique']:

                        links[sc.pipeEscape(tech['_link'])] = [
                            sc.pipeEscape(it['_link']) for _, it in tech['_children'].items()
                        ]
        
                outfile.write(tactic_temp.render(
                    name=tactic['name'],
                    description=tactic['description'],
                    footnote_links=tactic.get('_footnote_links', []),
                    tech_links=links))
        
        # TECHNIQUES
        for key, tech in techniques.items():
        
            detections = {}
            for comp in tech['_data_components'].values():
                for src in comp['_data_sources'].values():
                    if not src['_link'] in detections:
                        detections[src['_link']] = [comp]
                    else:
                        detections[src['_link']].append(comp)

            with tech['_path'].open('w+') as outfile:

                # ===========================
                # CRAFT AND WRITE FRONTMATTER
                # ===========================

                tags = [
                        "mitre/attack/technique",
                ]

                FM.write(outfile, dict(
                        tags=tags,
                        mitre_data=dict(
                            name=tech['name'],
                            id=tech['_ext_id'],
                            related_tactics=tech['_tactic_tag_names'],
                            linker_tags=[
                                f'mitre/attack/linker/{p}' for p in
                                tech['_tag_partials']
                            ]
                        )))

                # ======================
                # WRITE STANDARD CONTENT
                # ======================
        
                outfile.write(technique_temp.render(
                    name=tech['name'],
                    tag_partials=tech['_tag_partials'],
                    name_tag=tech['_tag_name'],
                    tactic_names=tech['_tactic_tag_names'],
                    footnote_links=tech.get('_footnote_links',[]),
                    identifier=tech.get('_ext_id'),
                    description=tech['description'],
                    ext_references=tech['_external_reference_links'],
                    permissions_required=tech.get('x_mitre_permissions_required', None),
                    platforms=tech.get('x_mitre_platforms', None),
                    detection=tech.get('x_mitre_detection', None),
                    detections=detections,
                    tool_links=[t['_link'] for t in tech['_tools'].values()],
                    tactic_links=[t['_link'] for t in tech['_tactics'].values()],
                    child_links=[t['_link'] for t in tech['_children'].values()],
                    parent_links=[t['_link'] for t in tech['_parents'].values()]))
        
        # DATA SOURCES
        for key, src in data_sources.items():
        
            with src['_path'].open('w+') as outfile:
        
                outfile.write(data_src_temp.render(
                    name=src['name'],
                    identifier=src.get('_ext_id'),
                    footnote_links=src.get('_footnote_links',[]),
                    description=src['description'],
                    data_component_links=[dc['_link'] for dc in src['_data_components'].values()],
                    ext_references=src['_external_reference_links'],
                    tactic_links=[t['_link'] for t in src['_tactics'].values()],
                    technique_links=[t['_link'] for t in src['_techniques'].values()]))
        
        # DATA COMPONENTS
        for key, comp in data_components.items():
        
            with comp['_path'].open('w+') as outfile:
        
                outfile.write(data_comp_temp.render(
                    name=comp['name'],
                    footnote_links=comp.get('_footnote_links',[]),
                    identifier=comp.get('_ext_id'),
                    description=comp['description'],
                    data_source_links=[src['_link'] for src in comp['_data_sources'].values()],
                    tactic_links=[t['_link'] for t in comp['_tactics'].values()],
                    technique_links=[t['_link'] for t in comp['_techniques'].values()]))

        # TOOLS
        for key, tool in tools.items():

            techniques_used = []

            for _id, tech in tool['_techniques'].items():
                rel = tech['_tool_relationships'].subkey('source_ref', key)
                if not rel: continue
                techniques_used.append(
                    (tech['name'], tech['_link'], rel['description'],)
                )

            with tool['_path'].open('w+') as outfile:

                outfile.write(tool_temp.render(
                    name=tool['name'],
                    footnote_links=tool.get('_footnote_links',[]),
                    identifier=tool.get('_ext_id'),
                    description=tool['description'],
                    platforms=tool.get('x_mitre_platforms', None),
                    ext_references=tool['_external_reference_links'],
                    techniques_used=techniques_used))

        # MALWARE
        for key, malware in malwares.items():

            techniques_used = []

            for _id, tech in malware['_techniques'].items():
                rel = tech['_malware_relationships'].subkey('source_ref', key)
                if not rel: continue
                techniques_used.append(
                    (tech['name'], tech['_link'], rel['description'],)
                )

            with malware['_path'].open('w+') as outfile:

                outfile.write(malware_temp.render(
                    name=malware['name'],
                    footnote_links=malware.get('_footnote_links',[]),
                    identifier=malware.get('_ext_id'),
                    description=malware['description'],
                    platforms=malware.get('x_mitre_platforms', None),
                    ext_references=malware['_external_reference_links'],
                    techniques_used=techniques_used))

        if clean_up:
            Build.log.info('Deleting attack-stix-data')
            shutil.rmtree('attack-stix-data')

        Build.log.info('Execution complete')

    def __call__(self, *args, **kwargs):

        return Build.build(*args, **kwargs)
