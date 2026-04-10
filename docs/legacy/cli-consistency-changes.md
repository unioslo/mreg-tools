# CLI Consistency Changes

I asked Claude to review all options in 2.0 and standardize their naming and descriptions across all commands. Furthermore, I asked it to cross-reference against 1.0 to ensure that all options from 1.0 were either unchanged or kept as aliases in 2.0. This is its summary.

----

Summary of changes made to standardize CLI options across all commands in `mreg_tools/commands/`. Some of these changes only affected options introduced in 2.0, while others were made to options that existed in 1.0.

## Changes by type

### 1. Help text capitalization

All help strings are now written in sentence case (first word capitalized). Five commands previously used all-lowercase help text.

**Affected:** `hostgroup-ldif`, `hosts-ldif`, `network-ldif`, `get-zonefiles`, `get-dhcphosts`

| Option | Before | After |
|--------|--------|-------|
| `--force`/`--force-check` | `"force refresh of data from mreg"` | `"Force refresh of data from mreg"` |
| `--ignore-size-change` | `"ignore size changes when writing …"` | `"Ignore size changes when writing …"` |
| `--use-saved-data` | `"force use saved data from previous runs…"` | `"Use saved data from previous runs…"` |

---

### 2. Standardize `--use-saved-data` description

The phrase `"force use saved data"` was ambiguous and redundant. Standardized to `"Use saved data from previous runs. Takes precedence over --force"` across all commands.

**Affected:** `hostgroup-ldif`, `hosts-ldif`, `network-ldif`, `get-zonefiles`, `get-dhcphosts`, `get-hostpolicy`, `get-hostinfo`

(`network-import` already used the correct phrasing.)

---

### 3. Fix wrong `--ignore-size-change` description in `get-dhcphosts`

The description incorrectly referred to "zone files" (copy-pasted from `get-zonefiles`).

**Affected:** `get-dhcphosts`

| Before | After |
|--------|-------|
| `"ignore size changes when writing the zone files"` | `"Ignore size changes when writing the output files"` |

---

### 4. Standardize `--filename` description

**Affected:** `hostgroup-ldif`, `hosts-ldif`, `network-ldif`, `get-hostinfo`

| Before | After |
|--------|-------|
| `"output filename for the ldif file"` | `"Output filename"` |
| `"Filename for the output file"` | `"Output filename"` |

---

### 5. Remove `--filename` from `get-zonefiles`

`get-zonefiles` writes multiple zone files, each named by `destname` from the config. The `--filename` option set `conf.get_zonefiles.filename`, which is never read by the command — making it a no-op. The option has been removed to avoid confusion.

**Affected:** `get-zonefiles`

---

### 6. Rename `--tagsfile` → `--tags-file` in `network-import`

Corrected to follow the kebab-case convention used by all other multi-word options (`--force-check`, `--ignore-size-change`, `--use-saved-data`, `--max-size-change`).

**Note:** `--tagsfile` was not present in 1.0 (the tags file was read from the config file). No backwards-compatibility alias is required.

**Affected:** `network-import`

---

### 7. Rename `--dryrun` → `--dry-run` in `network-import`

Corrected to follow kebab-case convention. 1.0 used `--dryrun`, so `--dryrun` is kept as a **hidden alias** for backwards compatibility.

The description was also expanded from `"Dryrun"` to `"Perform a dry run without making changes to mreg"`.

**Affected:** `network-import`

| Primary name | Aliases | Description |
|---|---|---|
| `--dry-run` | `--dryrun` (hidden) | `"Perform a dry run without making changes to mreg"` |

---

### 8. Improve `--hosts` description in `get-dhcphosts`

**Affected:** `get-dhcphosts`

| Before | After |
|--------|-------|
| `"which hosts to export"` | `"IP version of hosts to export (ipv4, ipv6, ipv6byipv4)"` |

---

## Backwards compatibility notes

All changes were cross-referenced against 1.0 scripts.

| Option in 1.0 | Affected 1.0 scripts | Status in 2.0 |
|---|---|---|
| `--force` | all | ✓ unchanged (primary name) |
| `--force-check` | `hosts-ldif`, `network-ldif` | ✓ kept as alias for `--force` |
| `--ignore-size-change` | `hosts-ldif`, `network-ldif` | ✓ unchanged |
| `--use-saved-data` | `hosts-ldif` | ✓ unchanged |
| `--force-size-change` | `network-import` | ✓ kept as alias for `--ignore-size-change` |
| `--max-size-change` | `network-import` | ✓ unchanged |
| `--dryrun` | `network-import` | ✓ kept as hidden alias for `--dry-run` |
| `networkfile` (positional) | `network-import` | ✓ unchanged (kept as positional argument) |

## Options not yet changed

- `--config` (deprecated, hidden) on `hostgroup-ldif`, `hosts-ldif`, `network-import`: left in place pending a potential implementation to parse old-style config files.
