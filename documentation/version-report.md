# Version & environment reporting

ContainRE exposes its own version together with the versions of its direct
dependencies and the relevant host/system software. The same data is available
four ways, all backed by one function (`containre.version_info`):

| Surface | Form |
| --- | --- |
| `containre --version` | plain-text report (format below) |
| `GET /api/version` | JSON object |
| Web UI → **About** tab | rendered from `GET /api/version` |
| `containre.version_info()` / `containre.version_report()` | Python API |

## Python API

```python
import containre

containre.version_info()      # -> dict  (structured; see JSON shape below)
containre.version_report()    # -> str   (the plain-text report below)
containre.version_report(containre.version_info())   # render a pre-fetched dict
```

## JSON shape (`GET /api/version` and `version_info()`)

```json
{
  "containre": "0.2.1",
  "dependencies": { "python-ptrace": "0.9.9", "zstandard": null, "...": "..." },
  "system": { "python": "3.14.6", "docker": "28.2.2", "criu": null, "...": "..." }
}
```

- `containre` — the package version (string).
- `dependencies` — direct runtime dependencies keyed by their **distribution**
  name (e.g. `python-ptrace`, `yara-python`). A value of `null` means the
  dependency is not installed (e.g. the optional `zstandard` / `snapshots`
  extra).
- `system` — host/interpreter facts. Keys: `python`, `python_implementation`,
  `platform`, `system`, `release`, `machine`, `openssl`, `docker`, `criu`.
  `docker`/`criu` are `null` when the tool is absent.

## Plain-text report format — "containre version report v1"

`containre --version` prints exactly this shape (three blank-line-separated
sections):

```
containre 0.2.1

[dependencies]
python-ptrace=0.9.9
pyyaml=6.0.3
...
zstandard=not installed

[system]
python=3.14.6
platform=Linux-6.14.0-37-generic-x86_64-with-glibc2.41
docker=28.2.2
criu=not installed
...
```

### Parsing contract

The format is stable and designed to be parsed line-by-line:

1. **Line 1** is `containre <version>` — split on the first space; the second
   field is the package version.
2. Sections are separated by a **single blank line**. Blank lines are not
   otherwise significant.
3. A section begins with a header line `[<name>]`. The defined sections are
   `[dependencies]` and `[system]`, in that order.
4. Every non-header, non-blank line in a section is `key=value`. The key is
   everything before the **first** `=`; the value is everything after it (values
   may themselves contain `=` or spaces — e.g. the `openssl` value).
5. The literal value `not installed` means the item is absent (equivalent to
   `null` in the JSON form).

New keys may be added within a section in future versions; parsers should ignore
unknown keys rather than fail. The section set and line-1 form are the stable
contract.
