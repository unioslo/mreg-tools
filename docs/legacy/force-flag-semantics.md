# `--force` Flag Semantics in Legacy Scripts

I asked Claude to analyze how the `--force` flag (and related flags) were used across in 1.0. This is its analysis of the two distinct safety mechanisms that `--force` bypasses, how 1.0 were inconsistent in their flag naming, and how the new CLI resolves this.

---

Analysis of how `--force` (and related flags) are used in 1.0 scripts.


## Two distinct safety mechanisms

`--force` in 1.0 bypasses up to **two independent safety mechanisms**:

### 1. Data freshness check (bypass `updated_entries`)

Most scripts call `common.utils.updated_entries()` before doing any work. This function checks whether remote mreg data has actually changed since the last run by comparing the most-recently-updated entry's timestamp, record count, and ID against a cached JSON file stored in `workdir`.

```python
# common/utils.py
def updated_entries(conn, url, filename, obj_filter="page_size=1&ordering=-updated_at") -> bool:
    """Check if first entry is unchanged"""
    ...
    if old_data["count"] != new_data["count"]
       or old_data["results"][0]["id"] != new_data["results"][0]["id"]
       or old_updated_at < new_updated_at:
        write_json_file(filename, new_data)
        return True
    return False
```

If nothing has changed, the script exits early — no data is fetched and no files are written. With `--force`, this check is short-circuited:

```python
if common.utils.updated_entries(conn, url, "atoms.json") or force:
    atoms = get_atoms(atoms_url)
    create_atoms(atoms)
```

### 2. Output file size safety check (bypass `compare_file_size`)

`common.utils.write_file()` compares the new output file's line count against the existing file on disk. If the difference exceeds a threshold, it raises `TooManyLineChanges` and refuses to write — protecting against accidentally overwriting a good file with a drastically truncated one (e.g., due to a partial API response).

Thresholds from `common/utils.py`:

```python
# Maximum size change in percent for each line count threshold
COMPARE_LIMITS_LINES = {50: 50, 100: 20, 1000: 15, 10000: 10, sys.maxsize: 10}
```

With `--force`, this check is skipped via `ignore_size_change=True`:

```python
common.utils.write_file(filename, f, ignore_size_change=force)
```

---

## Flag naming across scripts

1.0 scripts were inconsistent about whether these two concerns were combined into a single flag or split into separate flags:

| 1.0 Script | Bypass data freshness check | Bypass size check |
|---|---|---|
| `get-dhcphosts` | `--force` (combined) | `--force` (combined) |
| `get-hostpolicy` | `--force` (combined) | `--force` (combined) |
| `get-hostinfo` | `--force` (combined) | `--force` (combined) |
| `hostgroup-ldif` | `--force` (combined) | `--force` (combined) |
| `get-zonefiles` | `--force` (combined) | `--force` (combined) |
| `network-ldif` | `--force-check` | `--ignore-size-change` |
| `hosts-ldif` | `--force-check` | `--ignore-size-change` |
| `network-import` | N/A | `--force-size-change` |

`zone-import` is a special case: it uses `-force` as a flag in the mreg CLI commands it *generates* (for adding hosts in zones not in `KNOWNZONES`), not as a CLI argument to the script itself.

---

## How 2.0 resolves this

mreg-tools 2.0 resolves this inconsistency by standardizing on two separate flags across all scripts:

- `--force` — bypasses the data freshness check (replaces `--force-check` as primary name; `--force-check` is kept as a hidden alias)
- `--ignore-size-change` — bypasses the file size safety check (replaces `--force-size-change` in `network-import`; kept as a hidden alias)

These two concerns are always kept as separate flags, following the pattern established by `network-ldif` and `hosts-ldif`.
