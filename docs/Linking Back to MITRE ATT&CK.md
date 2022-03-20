# Linking Back to MITRE ATT&CK

The `linker` subcommand in the `mitre-attack` module enumerates
associated notes by scraping metadata from the frontmatter embedded in each
non-MITRE file. An additional section will be suffixed to the end
of each tactic and technique where links are found:

```
# Vault Links

- [[Vault Link 1]]
- [[vault Link 2]]
```

These links then draw relationships between the ATT&CK framework
and your own notes, allowing for the relationships to be clearly
rendered in global/local graph views.

# The `mitre_data` Frontmatter Element

The following structure can be embedded in files that are intended
to link back to a MITRE ATT&CK tactic or technique.

```yaml
mitre_data:
  technique_ids:
    - Technique1Id
    - Technique2Id
tags:
  - mitre/attack/linker/<tactic_name>/<technique_name>
```

**Tips:**

- The `technique_id` and "linker tag" values can be obtained from
  the markdown files written to disk using the `build` subcommend.
- The `<technique_name>` component of the "linker tag" values can
  be omitted.

# Linker Tags

Linker tags are specially formatted tag values that map back
to a MITRE ATT&CK tactic and (optionally) technique name. The
technique Id value isn't descriptive and this is a more
natural method of determining which techniques a given note
should be linked to.
