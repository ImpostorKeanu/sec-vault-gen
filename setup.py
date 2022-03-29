import setuptools

DATA_EXTS = ['*.txt', '*.yaml', '*.xml', '*.md', '*.template']
# Read README.md as a variable to pass as the package's long
# description
with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

setuptools.setup(
    name='sec-vault-generator',
    version='0.0.0',
    author='Justin Angel',
    author_email='justin@arch4ngel.ninja',
    description='A framework to parse common things into an Obsidian vault.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/arch4ngel/sec-vault-generator',
    include_package_data=True,
    package_dir={'':'src'},
    packages=setuptools.find_packages(where='src'),
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
    ],
    python_requires='>=3.9',
    scripts=['sec-vault-generator'],
    package_data={
        'sec_vault_generator.templates':DATA_EXTS,
        'sec_vault_generator.templates.mitre_attack':DATA_EXTS,
        'sec_vault_generator.templates.network_scan':DATA_EXTS,
        'sec_vault_generator.templates.lolbas':DATA_EXTS,
        },
    install_requires=[
        'requests',
        'GitPython',
        'pyaml',
        'Jinja2',
        'parsuite'
    ]
)
