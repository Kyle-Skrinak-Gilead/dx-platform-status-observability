# jquery-check

## Why this exists

I need visibility into which jQuery versions run on our public web properties.
jQuery is a common source of security findings and an indicator of frontend
modernization status. This gives me a snapshot I can track over time.

## What the scripts do

**`apex_resolve_jquery.py`** (primary script) — For each domain, it resolves
the apex URL to its final HTTPS destination, then detects the jQuery version
loaded on that final page. Uses Playwright (real browser) plus httpx fallbacks.
This is the most thorough check.

**`apex_to_www.py`** — Checks only the redirect behavior of apex domains
(naked domain → www). No jQuery detection. Useful when I want to audit redirect
hygiene independently of page content.

## Detection methodology (apex_resolve_jquery.py)

jQuery counts as present only when there is strong evidence it is actually
loaded and executed, in this priority order:

1. Runtime global — `window.jQuery.fn.jquery` or `window.$.fn.jquery` via Playwright
2. Script filename — URL matches `jquery-X.Y.Z(.min).js`
3. JS file download — jQuery banner comment or `.fn.jquery` assignment found in
   the first 4000 bytes of the downloaded file

Dependency strings (e.g., "requires at least jQuery v1.9.1") and inline
comment mentions do not count as presence.

## What it does not measure

- jQuery loaded after initial page render (lazy-loaded, SPA routing)
- jQuery loaded inside iframes
- jQuery version on pages other than the homepage
- Whether jQuery is actually used or just included

## Input files

`domains.txt` — current working list of domains to check  
`domains-one.txt` — single-domain file for quick test runs

## Gotchas

- Some sites block headless browsers and return misleading results; `method=error`
  in the output flags these.
- Apex domains that are unreachable but have a working www version report
  `action=apex_unreachable_www_ok` — this is not an error, just a redirect
  pattern worth knowing.
- Run time scales with concurrency and site response times; 10 domains takes
  roughly 30–60 seconds at default concurrency.
