import asyncio
import csv
import re
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright, TimeoutError as PWTimeoutError

JQ_VERSION_RE = re.compile(r"\b(?:jQuery|jquery)\s*v?(\d+\.\d+\.\d+)\b", re.IGNORECASE)
JQ_IN_FILENAME_RE = re.compile(r"jquery(?:[-.](\d+\.\d+\.\d+))?(?:\.min)?\.js", re.IGNORECASE)

DEFAULT_TIMEOUT_MS = 20000

def normalize_url(domain: str) -> str:
    d = domain.strip()
    if not d:
        return ""
    if d.startswith("http://") or d.startswith("https://"):
        return d
    return "https://" + d

async def fetch_text(url: str, timeout_s: float = 15.0) -> str:
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; jquery-version-audit/1.0)"
    }
    async with httpx.AsyncClient(follow_redirects=True, timeout=timeout_s, headers=headers) as client:
        r = await client.get(url)
        r.raise_for_status()
        return r.text

def parse_jquery_from_script_src(html: str, base_url: str):
    soup = BeautifulSoup(html, "html.parser")
    scripts = soup.find_all("script", src=True)
    candidates = []
    for s in scripts:
        src = s.get("src", "").strip()
        if not src:
            continue
        full = urljoin(base_url, src)
        if "jquery" in src.lower():
            candidates.append(full)

    # First try: parse version from filename/path
    for u in candidates:
        m = re.search(r"/(\d+\.\d+\.\d+)/jquery(?:\.min)?\.js", u, re.IGNORECASE)
        if m:
            return m.group(1), u

        m2 = JQ_IN_FILENAME_RE.search(u)
        if m2 and m2.group(1):
            return m2.group(1), u

    return None, (candidates[0] if candidates else None)

async def parse_jquery_from_downloaded_js(js_url: str):
    if not js_url:
        return None
    try:
        js = await fetch_text(js_url, timeout_s=15.0)
    except Exception:
        return None
    m = JQ_VERSION_RE.search(js[:4000]) or JQ_VERSION_RE.search(js)
    if m:
        return m.group(1)
    return None

async def detect_runtime_jquery(page):
    # Run inside the page context
    return await page.evaluate("""
        () => {
          const v1 = (window.jQuery && window.jQuery.fn && window.jQuery.fn.jquery) ? window.jQuery.fn.jquery : null;
          const v2 = (window.$ && window.$.fn && window.$.fn.jquery) ? window.$.fn.jquery : null;
          return v1 || v2 || null;
        }
    """)

async def inspect_one(browser, domain: str):
    url = normalize_url(domain)
    if not url:
        return {"domain": domain, "final_url": "", "jquery_version": "", "method": "invalid", "notes": "empty input"}

    context = await browser.new_context()
    page = await context.new_page()
    final_url = ""
    notes = ""

    try:
        resp = await page.goto(url, wait_until="domcontentloaded", timeout=DEFAULT_TIMEOUT_MS)
        # Some sites block https; try http if https fails hard.
        if resp is None:
            final_url = page.url
        else:
            final_url = page.url

        # Let late scripts run a bit
        try:
            await page.wait_for_load_state("networkidle", timeout=8000)
        except PWTimeoutError:
            pass

        v = await detect_runtime_jquery(page)
        if v:
            await context.close()
            return {"domain": domain, "final_url": final_url, "jquery_version": v, "method": "runtime", "notes": ""}

        # Fallback: parse HTML for jquery script tags, then maybe download the JS
        html = await page.content()
        version, js_url = parse_jquery_from_script_src(html, final_url)

        if version:
            await context.close()
            return {"domain": domain, "final_url": final_url, "jquery_version": version, "method": "script-src", "notes": js_url or ""}

        # If we found a candidate jquery URL but no version in filename, download and inspect header
        if js_url:
            v2 = await parse_jquery_from_downloaded_js(js_url)
            if v2:
                await context.close()
                return {"domain": domain, "final_url": final_url, "jquery_version": v2, "method": "download-js", "notes": js_url}

        await context.close()
        return {"domain": domain, "final_url": final_url, "jquery_version": "", "method": "not-found", "notes": "no global jQuery and no detectable jquery src"}

    except Exception as e:
        try:
            final_url = page.url
        except Exception:
            final_url = ""
        try:
            await context.close()
        except Exception:
            pass
        return {"domain": domain, "final_url": final_url, "jquery_version": "", "method": "error", "notes": str(e)}

async def run(domains, out_csv="jquery_versions.csv", concurrency=6):
    sem = asyncio.Semaphore(concurrency)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, channel="chrome")
        results = []

        async def wrapped(d):
            async with sem:
                return await inspect_one(browser, d)

        tasks = [asyncio.create_task(wrapped(d)) for d in domains if d.strip()]
        for t in asyncio.as_completed(tasks):
            results.append(await t)

        await browser.close()

    # Write CSV
    fields = ["domain", "final_url", "jquery_version", "method", "notes"]
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in results:
            w.writerow(r)

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python detect_jquery.py domains.txt [output.csv]")
        raise SystemExit(2)

    domains_file = sys.argv[1]
    out_csv = sys.argv[2] if len(sys.argv) > 2 else "jquery_versions.csv"

    with open(domains_file, "r", encoding="utf-8") as f:
        domains = [line.strip() for line in f if line.strip()]

    asyncio.run(run(domains, out_csv=out_csv))
    print(f"Wrote {out_csv}")
