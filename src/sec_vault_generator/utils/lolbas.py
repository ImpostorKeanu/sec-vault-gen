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
from copy import deepcopy
import re
import json
import shutil
from sys import exit

lolbas_temp = jenv.get_template('lolbas/base.md')

class Build(Util):

    log = getLogger('lolbas.build')

    ap = arg_parser = ArgumentParser(
        description='Build the LOLBAS framework.',
        parents=(
            args.outputDirectory(('--output-directory', '-od',),
                required=False,
                help='Directory to receive output. '+ART),
            args.cleanUp(),),
        add_help=False)

    ap.add_argument('--lolbas-repo',
        default='https://github.com/LOLBAS-Project/LOLBAS',
        help='Repository containing the LOLBAS content. '+ART)

    ap._action_groups[1].title = 'arguments'

    @staticmethod
    def build(output_directory:str, lolbas_repo:str, clean_up:bool):

        out_dir = output_directory = Path(output_directory)

        # ======================
        # PREPARE THE REPOSITORY
        # ======================

        if not Path('LOLBAS').exists():

            Build.log.info('Cloning the LOLBAS repository.')

            repo = sc.cloneRepo(url=lolbas_repo,
                target='LOLBAS')

        else:

            Build.log.info('Using cached LOLBAS repository.')

        # ======================
        # BEGIN PARSING THE DATA
        # ======================

        for d in Path('LOLBAS/yml').glob('*'):

            if not d.is_dir(): continue

            type_dir = out_dir / d.name
            type_dir.mkdir(parents=True, exist_ok=True)

            # ====================
            # GET FRONTMATTER DATA
            # ====================

            for infile in d.glob('*.yml'):
                with infile.open() as i:
                    fm = FM.read(i)

                # =============================
                # ORGANIZE COMMANDS BY CATEGORY
                # =============================

                categories = list(set([c['Category'] for c in fm['Commands']]))
                commands_by_category = {}
                for cat in categories:
                    commands_by_category[cat] = [
                        c for c in fm['Commands'] if c['Category'] == cat
                    ]

                technique_ids = []
                for c in fm['Commands']:
                    id_ = c.get('MitreID')
                    if not id_ in technique_ids:
                        technique_ids.append(id_)
                        fm['tags'].append(Tag(f'lolbas/{d.name.lower()}'))

                fm['mitre_data'] = dict(technique_ids=technique_ids)

                # ========================
                # PREPARE ACKNOWLEDGEMENTS
                # ========================
                
                acks = []
                for ack in fm.get('Acknowledgement',[]):
                    person, handle = ack.get('Person'), ack.get('Handle')
                    if person and not handle:
                        acks.append(person)
                    elif handle and not person:
                        acks.append(handle)
                    elif handle and person:
                        acks.append(f'{person} ({handle})')
    
                # ========================
                # WRITE THE LOLBAS TO DISK
                # ========================
    
                outfile = type_dir / (sc.fsSafeName(fm['Name'])+'.md')
                with outfile.open('w+') as of:

                    # =================
                    # WRITE FRONTMATTER
                    # =================

                    FM.write(of, fm)

                    # ==================
                    # WRITE THE TEMPLATE
                    # ==================

                    of.write(
                        lolbas_temp.render(
                            name=fm['Name'],
                            author=fm['Author'],
                            created=fm['Created'],
                            description=fm['Description'],
                            paths=[f"`{p['Path']}`" for p in fm.get('Full_Path',[])],
                            resources=[r['Link'] for r in fm.get('Resources',[])],
                            acks=acks,
                            commands_by_category=commands_by_category))

        if clean_up:
            Build.log.info('Deleting LOLBAS directory')
            shutil.rmtree('LOLBAS')

        Build.log.info('Execution complete')

    def __call__(self, *args, **kwargs):

        return Build.build(*args, **kwargs)



