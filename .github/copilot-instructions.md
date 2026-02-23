# Copilot Instructions for dx-platform-status-observability

## Context

I use this repository for administrative, leadership-level oversight reporting across DX CMS and non-CMS web platforms. These scripts observe and report only. They do not support production deployments, daily operations, or incident response.

## Language and Voice

- Always use active voice. Never use passive voice.
- Write comments only when the code needs clarification. Do not comment the obvious.
- Be concise and direct. No filler, no hedging.

## Code Style

- Python 3 only. Invoke as `python3`. Include `#!/usr/bin/env python3` shebangs.
- Prefer the standard library. Only introduce third-party packages when the standard library cannot do the job, and say so explicitly.
- Every script has one clear purpose, one entry point, and this structure:

```python
def main():
    ...

if __name__ == "__main__":
    main()
```

- Scripts run directly: `python3 scripts/<area>/<script>.py`
- No shared runners, no orchestration wrappers, no frameworks.

## Virtual Environments

- Scripts that need third-party packages get a `.venv` scoped to their subdirectory — not a repo-wide environment.
- Create it inside the script's directory: `cd scripts/<area> && python3 -m venv .venv`
- Activate before running: `source scripts/<area>/.venv/bin/activate`
- `.venv` directories are gitignored; never suggest committing them.
- When suggesting a new third-party dependency, name the `pip install` command and note which script directory owns the `.venv`.

## Repository Structure

```
scripts/      # One subdirectory per reporting area; each script is self-contained
lib/          # Shared utilities only — used by 2+ scripts; no premature abstraction
configs/      # Shared input data (site lists, thresholds) used across multiple scripts
outputs/      # Generated output; gitignored; do not commit
notes/        # Reasoning capture — why scripts exist, what they do not measure
scratch/      # Experiments; not for production scripts
```

Script-specific input files (e.g., a domain list used by only one script) live co-located in that script's subdirectory.

## What to Avoid

- Do not suggest frameworks, base classes, managers, pipelines, or orchestration layers.
- Do not suggest CI/CD, GitHub Actions, or workflow automation unless I ask.
- Do not abstract until a pattern appears at least twice.
- Do not use words like "operational," "deploy," or "production" to describe what these scripts do.
- Do not commit outputs, virtual environments, or `.DS_Store` files.

## Scope

This repo is for my use as a senior manager. It is not a team platform, not a runbook, and not a delivery artifact. Suggestions should fit a single-contributor, analytical workspace.
