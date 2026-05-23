# CLI

How to run flawed and read its output.

## Running a scan

```bash
flawed scan TARGET        # scan a repository (TARGET is a filesystem path)
flawed scan .             # scan the current directory
flawed .                  # shorthand for `flawed scan .`
```

A scan runs the full pipeline — structural extraction (Layer 1), framework
interpretation (Layer 2), and rule execution (Layer 3) — and prints findings.
The bundled rules (`endpoints`, `request-inputs`, `route-guards`,
`value-flow`, `type-disagreements`) run by default; point `--rules-dir` at your
own rule modules to run those instead.

Findings print to **stdout**; progress and the run summary go to **stderr**, so
`flawed scan TARGET > findings.txt` captures only the findings.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | no finding at or above `--fail-on` (default: `medium`) |
| `1` | a finding at or above `--fail-on` exists |
| `2` | usage / configuration error |
| `3` | internal / analysis error |
| `124` | a layer or the overall scan timed out |

`--fail-on` governs exit `1` independently of what is displayed:

```bash
flawed scan . --fail-on high      # exit 1 only on high+ findings
```

## Choosing which rules run

```bash
flawed scan TARGET --rules-dir ./my_rules   # run your own rule modules instead
flawed scan TARGET --smoke                  # fast curated subset (quick iteration)
flawed rules                                # list the loaded rules
flawed scan TARGET -i "value-*"             # only rules whose id matches a glob
flawed scan TARGET -e endpoints             # exclude rules by glob
flawed scan TARGET -I '^value' -E 'flow$'   # include/exclude by regex
```

`--rules-dir` is repeatable and overrides the built-in set, so one run can
combine several custom rule roots. Rule-id matching is separator-insensitive
(`-` and `_` are interchangeable). See [Writing rules](writing-rules.md) to
author your own.

## Providers

Providers supply the framework knowledge that turns raw structure into routes,
inputs, effects, and checks. Selection is automatic from detected imports; you
can override it:

```bash
flawed providers list                       # available providers
flawed providers show <id>                  # one provider's patterns
flawed providers coverage TARGET            # which providers activated on a repo
flawed scan TARGET --provider <id>          # force-enable (repeatable)
flawed scan TARGET --no-provider <id>       # force-disable (repeatable)
```

See [Authoring a provider](provider-authoring.md) to teach the engine a new
framework.

## Output formats

```bash
flawed scan TARGET                          # human-readable text (default)
flawed scan TARGET --json > out.json        # machine-readable findings
flawed scan TARGET --sarif > out.sarif      # SARIF 2.1.0 for code scanning
flawed scan TARGET --output-format json     # equivalent to --json
flawed scan TARGET --summary                # per-rule breakdown after the scan
flawed -v scan TARGET                       # phase timing + per-finding evidence
```

A `--json` capture carries severity, location, evidence chains, analysis gaps,
and `metadata.timing.*`. It is the document the
[Python API](python-api.md#exploring-findings) and `flawed explore` read back.

## Reviewing results

```bash
flawed explore out.json                     # REPL / one-shot summary over findings
flawed explore out.json --group-by rule     # counts by rule | severity | file
flawed explore out.json --rule <rule-id>    # list one rule's findings
flawed explore out.json --diff baseline.json # added / removed vs a baseline
flawed explain <rule-id>                     # what a rule detects and why
```

`flawed explore` opens a Python REPL with the findings preloaded as `findings`
when run on a TTY, and prints a summary otherwise. The programmatic equivalent is
`load_findings()` — see [Python API](python-api.md#exploring-findings).

## Incremental and CI scanning

```bash
flawed scan TARGET --baseline-commit main   # only findings new since a git ref
flawed scan TARGET --strict                 # require a reason on every inline ignore
flawed scan TARGET --no-ignore              # ignore a .flawedignore file
flawed scan TARGET --refresh                # recompute, ignoring the results cache
flawed scan TARGET --no-cache               # do not read or write the results cache
```

`--baseline-commit` matches on a location-stable key, so a pure line shift does
not resurface a finding. Inline `# flawed: ignore -- <reason>` directives suppress
a finding at a site; `--strict` rejects unreasoned ones.

## Layers and timeouts

```bash
flawed scan TARGET --no-semantic            # Layer 1 only (structure, no providers/rules)
flawed scan TARGET --timeout 600            # overall budget (seconds)
flawed scan TARGET --layer-timeout 300      # per-layer budget
flawed scan TARGET --rule-timeout 60        # per-rule budget
flawed scan TARGET --profile profile.json   # structured timing/telemetry report
```

## Configuration

Resolved configuration lives at `~/.config/flawed/config.yaml`:

```yaml
data_dir: <path>            # Layer 1 cache location
repo_local: false           # use a per-repo cache directory
type_enrichment:
  enable_mypy_batch: false  # opt-in mypy batch as a second type oracle
providers:
  base_dir: <path>          # base for relative provider paths
  paths: []                 # additional provider module locations
```

Inspect and validate it:

```bash
flawed config show          # fully resolved configuration
flawed config show --repo TARGET
flawed config check         # validate all config files
```

Layer 1 results are cached by content hash, so repeat scans of an unchanged tree
skip extraction. The per-rule results cache (`flawed cache status|clear`) is a
separate, content-hash-keyed memo for detector outputs.
