# Installation

## Requirements

- Git
- Python >= 3.9

## Supported Platforms

Though **untestested**, Python's native `pathlib.Path` module was used during development, so this
utility should function on all platforms.

## Preface: virtualenv

If desired, [virtualenv](https://virtualenv.pypa.io/en/latest/) can be used to isolate your package
environment. You'll probably want to run these commands from the directory where you'll be cloning
this repository.

```bash
python3 -m pip install virtualenv
python3 -m venv env
source env/bin/activate
```

## Procedure

Just clone the repository, install requirements via PIP, and run the utility:

```bash
git clone https://github.com/arch4ngel/sec-vault-gen
cd sec-vault-gen
python3 -m pip install -r requirements.txt
python3 generator.py --help
```
