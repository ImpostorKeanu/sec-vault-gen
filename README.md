# Security Vault Generator

Quickly parse, format, and output common frameworks/content for [Obsidian.md](https://obsidian.md).

# Quickstart

_This assumes all packages have been installed via PIP. See [Installation](docs/Installation.md)
for steps on this process._

Just execute the proper `build` subcommand and `generator.py` will:

1. Clone necessary repositories.
2. Parse all artifacts.
3. Embed frontmatter with tagging.
4. Format them to `.md` files.
5. And dump the files to disk in a directory of your choice.
6. 

Assuming your vault is named `TheVault`, these commands should work
to build out the MITRE ATT&CK framework and LOLBAS:

**Tip:** Select a directory in the target Obsidian vault  as an output directory using the `-od` flag
for each subcommand.

```bash
python3 generator.py mitre-attack build -od ~/TheVault/MITRE\ Attack/
python3 generator.py lolbas build -od ~/TheVault/LOLBAS/
```

![execution](docs/resources/execution.png)

Now all you have to do is open the vault in Obsidian:

![obsidian](docs/resources/obsidian_attack.png)

# Docs

- [Installation](docs/Installation.md)

# Pending Enhancements

- Establish links between technique files and LOLBAS items.
