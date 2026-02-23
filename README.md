# dx-platform-status-observability

I use this repository to run administrative oversight reporting for leadership
across DX CMS and non-CMS web platforms. These scripts observe and report only;
they do not support production deployments or daily operations.

## Repo structure

```
scripts/          One subdirectory per reporting area; each script runs independently
lib/              Shared utilities used by 2+ scripts
configs/          Shared input data (site lists, thresholds) used across scripts
outputs/          Generated output — gitignored; run locally only
notes/            Reasoning behind each script area: why it exists, what it skips
scratch/          Experiments; not for production scripts
```

## Scripts

| Area | Script | What it does |
|------|--------|--------------|
| `jquery-check` | `apex_resolve_jquery.py` | Resolves apex domains to their final HTTPS URL and detects the jQuery version loaded on the homepage |
| `jquery-check` | `apex_to_www.py` | Checks whether apex (naked) domains redirect to www over HTTPS and reports the full redirect chain |
| `broken_links` | `broken_links.py` | *(not yet implemented)* |
| `cert_expiry` | `cert_expiry.py` | *(not yet implemented)* |
| `http_health` | `http_health.py` | *(not yet implemented)* |

## Dependencies

Scripts in `scripts/jquery-check/` require a virtual environment. Set it up once:

```bash
cd scripts/jquery-check
python3 -m venv .venv
source .venv/bin/activate
pip install httpx beautifulsoup4 playwright truststore
playwright install chromium
```

All other scripts use the standard library only.

## Running a script

Activate the virtual environment first if the script needs it, then run directly:

```bash
# jQuery detection — resolves apex + detects jQuery version (primary)
source scripts/jquery-check/.venv/bin/activate
python3 scripts/jquery-check/apex_resolve_jquery.py scripts/jquery-check/domains.txt \
  --out outputs/jquery_report.csv --progress

# Apex-to-www redirect check only
python3 scripts/jquery-check/apex_to_www.py scripts/jquery-check/domains.txt \
  --out outputs/apex_www_report.csv --progress
```

Output goes to `outputs/`. That directory is gitignored.

