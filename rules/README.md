# ErrataGuard Rule Specifications

This directory contains external rule definitions for ErrataGuard in YAML format.

## Authoritativeness Guideline

> [!IMPORTANT]
> Rules in `rules/demo/` are explicitly marked with `authoritative: false`. They are synthetic rules designed to demonstrate the static verification engine and test the two-stage analysis pipeline.
> Real ARM errata rules (such as Cortex-A53 835769 or 843419) will be added once backed by verified, authoritative ARM Silicon Errata documentation.

## Rule Schema

Each rule YAML file defines:

| Field | Type | Description |
|---|---|---|
| `erratum` / `erratum_id` | string | Unique identifier for the erratum (e.g. `A53-DEMO-001`) |
| `title` | string | Human-readable title describing the issue |
| `architecture` | string | Target architecture (`AArch64`) |
| `cpu` | string | Target CPU core (e.g. `Cortex-A53`) |
| `authoritative` | boolean | Set `false` for demo/synthetic rules, `true` for verified ARM errata |
| `affected_revisions` | list[string] | List of affected hardware revisions (e.g. `['r0p0', 'r0p1', 'r0p2']`) |
| `candidate` | mapping | Stage 1 fast filter criteria: `mnemonics`, `classes`, `require_dest_reg` |
| `conditions` | list[mapping] | Stage 2 contextual conditions (`instruction_sequence`, `register_dependency`, etc.) |
| `workaround` | mapping | Mitigation description and suggested remedy |
| `references` | list[string] | Authoritative citations or demo notice |
| `severity` | string | Severity level (`warning`, `error`, `critical`) |

## Fast Candidate Filtering

Stage 1 uses the `candidate` block to rapidly filter out irrelevant instructions without constructing contexts:

```yaml
candidate:
  mnemonics:
    - adrp
```

Instructions matching candidate mnemonics are passed to Stage 2 for contextual and relational condition verification.
