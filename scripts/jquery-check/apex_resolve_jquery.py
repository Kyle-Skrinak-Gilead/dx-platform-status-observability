#!/usr/bin/env python3
"""Resolve apex domains to their final HTTPS URL and detect jQuery *present* on the homepage.

Script version: 2026.02.23.3

Definition of "present"
A jQuery version counts as present only when there is strong evidence that jQuery core is loaded/executed:
- Runtime global version from Playwright: window.jQuery?.fn?.jquery or window.$?.fn?.jquery
- A script URL that is a jQuery core file: jquery-X.Y.Z(.min).js
- jQuery core signature found in a downloaded JS file (header or assignments):
    - /*! jQuery vX.Y.Z ... */
    - jQuery.fn.jquery = "X.Y.Z"
    - jQuery.prototype.jquery = "X.Y.Z"

Non-goals
- We do NOT treat dependency requirement strings (e.g. "requires at least jQuery v1.9.1") as presence.
- We do NOT report versions that are only mentioned in strings/comments.

CSV columns
- script_version: version of this script
- jquery_version: effective runtime global jQuery version if available, else NOT_FOUND / MULTIPLE / SKIPPED_NON_HTML.
- jquery_runtime_version: runtime global jQuery version from Playwright evaluation (may be blank).
- jquery_runtime_instances: JSON list of global names on window that look like jQuery functions, with their versions.
- jquery_versions_present: semicolon-delimited list of present versions.
- jquery_multiple_present: Y if more than one present version detected, else N.
- jquery_reference_urls: semicolon-delimited list of script/resource URLs containing "jquery".
- jquery_evidence: JSON mapping from version -> list of evidence objects.
  Evidence object fields:
    - kind: runtime | script_src | js_core
    - source: URL or "INLINE" or page URL
    - match: short snippet around the match

Deduplication
- Evidence entries are deduplicated by (kind, source, match) for clarity.

Playwright notes
- page.goto() can throw "Download is starting" for direct-download URLs (PDF, etc.). Those are not HTML.
"""

__version__ = "2026.02.23.3"

import argparse
import asyncio
import csv
import json
import os
import re
import sys
from dataclasses import dataclass
from typing import Optional, Tuple, Set, Dict, Any, List
from urllib.parse import urlparse, urljoin

import httpx

try:
    import truststore  # type: ignore
    truststore.inject_into_ssl()
except Exception:
    pass

from bs4 import BeautifulSoup

# Strong jQuery core signatures
JQ_FN_JQUERY_RE = re.compile(r"\bjQuery\.fn\.jquery\s*=\s*['\"](\d+\.\d+\.\d+)['\"]")
JQ_PROTOTYPE_JQUERY_RE = re.compile(r"\bjQuery\.prototype\.jquery\s*=\s*['\"](\d+\.\d+\.\d+)['\"]")
JQ_HEADER_RE = re.compile(r"/\*!\s*jQuery\s*v?(\d+\.\d+\.\d+)\b", re.IGNORECASE)

# Script src pattern
JQ_SRC_RE = re.compile(r"jquery(?:\.min)?-(\d+\.\d+\.\d+)(?:\.min)?\.js", re.IGNORECASE)

# Non-HTML extensions
NON_HTML_EXTS = {
    ".pdf", ".zip", ".rar", ".7z",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".csv", ".tsv",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".mp3", ".mp4", ".wav", ".mov",
    ".json", ".xml",
}


def _clip(s: str, n: int = 180) -> str:
    s = s.replace("\r", " ").replace("\n", " ")
    s = re.sub(r"\s+", " ", s).strip()
    return s if len(s) <= n else s[: n - 3] + "..."


def _context(text: str, start: int, end: int, window: int = 80) -> str:
    a = max(0, start - window)
    b = min(len(text), end + window)
    return text[a:b]


def _add_evidence(evidence: Dict[str, List[Dict[str, str]]], version: str, kind: str, source: str, match: str) -> None:
    """Add evidence, deduplicating by (kind, source, match)."""
    if not version:
        return
    item = {"kind": kind, "source": source, "match": _clip(match)}
    lst = evidence.setdefault(version, [])
    for existing in lst:
        if existing.get("kind") == item["kind"] and existing.get("source") == item["source"] and existing.get("match") == item["match"]:
            return
    lst.append(item)


@dataclass
class Row:
    naked_domain: str
    resolving_endpoint: str
    script_version: str
    jquery_version: str
    jquery_runtime_version: str
    jquery_runtime_instances: str
    jquery_versions_present: str
    jquery_multiple_present: str
    jquery_reference_urls: str
    jquery_evidence: str


def normalize_domain(line: str) -> str:
    v = line.strip()
    if not v or v.startswith("#"):
        return ""
    v = v.split()[0].strip()
    if "://" in v:
        host = (urlparse(v).hostname or "").lower()
    else:
        host = (urlparse("https://" + v).hostname or "").lower()
    host = host.strip().strip(".")
    if host.startswith("www."):
        host = host[4:]
    return host


def is_non_html_url(url: str) -> bool:
    try:
        path = urlparse(url).path.lower()
    except Exception:
        return False
    return any(path.endswith(ext) for ext in NON_HTML_EXTS)


class Net:
    def __init__(self, client: httpx.AsyncClient, sem: asyncio.Semaphore, timeout: httpx.Timeout, retries: int):
        self.client = client
        self.sem = sem
        self.timeout = timeout
        self.retries = retries

    async def get(self, url: str, *, follow_redirects: bool = True) -> httpx.Response:
        attempt = 0
        backoff = 0.5
        last_exc: Optional[Exception] = None
        while attempt <= self.retries:
            attempt += 1
            try:
                async with self.sem:
                    return await self.client.get(url, follow_redirects=follow_redirects, timeout=self.timeout)
            except (httpx.PoolTimeout, httpx.ConnectTimeout, httpx.ReadTimeout, httpx.WriteTimeout) as e:
                last_exc = e
                if attempt > self.retries:
                    break
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 5.0)
            except httpx.RequestError:
                raise
        assert last_exc is not None
        raise last_exc


async def resolve_https_443(net: Net, apex: str) -> Tuple[str, str]:
    last_err = ""
    for host in (apex, f"www.{apex}"):
        url = f"https://{host}/"
        try:
            resp = await net.get(url, follow_redirects=True)
            return str(resp.url), ""
        except httpx.RequestError as e:
            last_err = f"{type(e).__name__}: {e}"
    return "", (last_err or "resolution failed")


async def fetch_html_httpx(net: Net, url: str) -> Tuple[str, str]:
    try:
        r = await net.get(url, follow_redirects=True)
        ct = (r.headers.get("content-type") or "").lower()
        cd = (r.headers.get("content-disposition") or "").lower()
        if "attachment" in cd:
            return "", f"NON_HTML: content-disposition={cd}"
        if ct and ("text/html" not in ct and "application/xhtml" not in ct):
            return "", f"NON_HTML: content-type={ct}"
        return r.text, ""
    except httpx.RequestError as e:
        return "", f"{type(e).__name__}: {e}"


async def fetch_text_limited(net: Net, url: str, max_bytes: int) -> Tuple[str, str]:
    try:
        r = await net.get(url, follow_redirects=True)
        b = r.content
        if max_bytes and len(b) > max_bytes:
            b = b[:max_bytes]
        try:
            txt = b.decode(r.encoding or "utf-8", errors="replace")
        except Exception:
            txt = b.decode("utf-8", errors="replace")
        return txt, ""
    except httpx.RequestError as e:
        return "", f"{type(e).__name__}: {e}"


def extract_present_from_text(text: str, source: str, evidence: Dict[str, List[Dict[str, str]]]) -> Set[str]:
    present: Set[str] = set()
    for rx in (JQ_FN_JQUERY_RE, JQ_PROTOTYPE_JQUERY_RE, JQ_HEADER_RE):
        for m in rx.finditer(text):
            v = m.group(1)
            present.add(v)
            _add_evidence(evidence, v, "js_core", source, _context(text, m.start(1), m.end(1)))
    return present


def collect_scripts(html: str, base_url: str, evidence: Dict[str, List[Dict[str, str]]]) -> Tuple[List[str], Set[str], Set[str]]:
    soup = BeautifulSoup(html, "html.parser")
    script_urls: List[str] = []
    present: Set[str] = set()
    jquery_refs: Set[str] = set()

    for s in soup.find_all("script"):
        src = s.get("src")
        if not src:
            continue
        full = urljoin(base_url, src)
        script_urls.append(full)
        if "jquery" in full.lower():
            jquery_refs.add(full)
        m = JQ_SRC_RE.search(full)
        if m:
            v = m.group(1)
            present.add(v)
            _add_evidence(evidence, v, "script_src", full, full)

    for s in soup.find_all("script"):
        if s.get("src"):
            continue
        txt = s.string
        if not txt:
            continue
        present.update(extract_present_from_text(txt, "INLINE", evidence))

    present.update(extract_present_from_text(html, base_url, evidence))

    seen = set()
    out_urls: List[str] = []
    for u in script_urls:
        if u not in seen:
            seen.add(u)
            out_urls.append(u)

    return out_urls, present, jquery_refs


async def scan_external_js(net: Net, script_urls: List[str], max_js_bytes: int, js_concurrency: int, evidence: Dict[str, List[Dict[str, str]]]) -> Tuple[Set[str], Set[str]]:
    if not script_urls:
        return set(), set()

    sem = asyncio.Semaphore(js_concurrency)
    present: Set[str] = set()
    jquery_refs: Set[str] = set()

    async def one(u: str) -> None:
        async with sem:
            txt, err = await fetch_text_limited(net, u, max_js_bytes)
            if err:
                return
            if "jquery" in u.lower():
                jquery_refs.add(u)
            present.update(extract_present_from_text(txt, u, evidence))

    await asyncio.gather(*[asyncio.create_task(one(u)) for u in script_urls], return_exceptions=True)
    return present, jquery_refs


async def fetch_playwright(url: str, timeout: float, headless: bool, channel: str, executable_path: str) -> Tuple[str, str, List[Dict[str, str]]]:
    try:
        from playwright.async_api import async_playwright, TimeoutError as PWTimeoutError  # type: ignore
    except Exception:
        return "", "", []

    async with async_playwright() as p:
        launch_kwargs: Dict[str, Any] = {"headless": headless}
        if channel:
            launch_kwargs["channel"] = channel
        if executable_path:
            launch_kwargs["executable_path"] = executable_path

        browser = await p.chromium.launch(**launch_kwargs)
        page = await browser.new_page()
        try:
            await page.goto(url, wait_until="networkidle", timeout=int(timeout * 1000))
        except PWTimeoutError:
            pass

        try:
            runtime_version = await page.evaluate(
                """() => {
                    const v1 = window.jQuery && window.jQuery.fn && window.jQuery.fn.jquery;
                    const v2 = window.$ && window.$.fn && window.$.fn.jquery;
                    return v1 || v2 || '';
                }"""
            )
        except Exception:
            runtime_version = ""

        try:
            runtime_instances = await page.evaluate(
                """() => {
                    const out = [];
                    for (const k of Object.getOwnPropertyNames(window)) {
                      try {
                        const v = window[k];
                        if (typeof v === 'function' && v.fn && typeof v.fn.jquery === 'string') {
                          out.push({ global: k, version: v.fn.jquery });
                        }
                      } catch (e) {}
                    }
                    const seen = new Set();
                    const uniq = [];
                    for (const x of out) {
                      const key = x.global + '|' + x.version;
                      if (!seen.has(key)) { seen.add(key); uniq.push(x); }
                    }
                    return uniq;
                }"""
            )
        except Exception:
            runtime_instances = []

        html = await page.content()
        await browser.close()

        return (runtime_version or ""), html, (runtime_instances or [])


def _sort_versions(vs: Set[str]) -> List[str]:
    def key(s: str):
        try:
            return tuple(int(x) for x in s.split('.'))
        except Exception:
            return (999, 999, 999)
    return sorted(vs, key=key)


async def detect_for_url(net: Net, final_url: str, timeout_seconds: float, max_js_bytes: int, js_concurrency: int, use_playwright: bool, headless: bool, playwright_channel: str, playwright_executable: str) -> Tuple[str, str, str, str, str, str, str]:
    if is_non_html_url(final_url):
        return "SKIPPED_NON_HTML", "", "[]", "", "N", "", "{}"

    html, fetch_err = await fetch_html_httpx(net, final_url)
    if fetch_err.startswith("NON_HTML:"):
        return "SKIPPED_NON_HTML", "", "[]", "", "N", "", "{}"
    if not html:
        return f"ERROR: {fetch_err}", "", "[]", "", "N", "", "{}"

    evidence: Dict[str, List[Dict[str, str]]] = {}

    script_urls, present_html, refs_html = collect_scripts(html, final_url, evidence)
    present_js, refs_js = await scan_external_js(net, script_urls, max_js_bytes, js_concurrency, evidence)

    present = set(present_html) | set(present_js)
    ref_urls = set(refs_html) | set(refs_js)

    runtime_version = ""
    runtime_instances: List[Dict[str, str]] = []

    if use_playwright:
        runtime_version, htmlp, runtime_instances = await fetch_playwright(final_url, timeout_seconds, headless, playwright_channel, playwright_executable)
        if runtime_version:
            present.add(runtime_version)
            _add_evidence(evidence, runtime_version, "runtime", final_url, f"runtime={runtime_version}")
        for inst in runtime_instances or []:
            v = (inst.get("version") or "").strip()
            if v:
                present.add(v)
                _add_evidence(evidence, v, "runtime", final_url, f"runtime_instance={inst.get('global')}:{v}")

        if htmlp:
            script_urls2, present_html2, refs_html2 = collect_scripts(htmlp, final_url, evidence)
            present_js2, refs_js2 = await scan_external_js(net, script_urls2, max_js_bytes, js_concurrency, evidence)
            present |= (present_html2 | present_js2)
            ref_urls |= (refs_html2 | refs_js2)

    present_sorted = _sort_versions(present)
    jquery_versions_present = ";".join(present_sorted)
    jquery_multiple_present = "Y" if len(present) > 1 else "N"

    jquery_version = runtime_version if runtime_version else ("NOT_FOUND" if len(present) == 0 else (present_sorted[0] if len(present) == 1 else "MULTIPLE"))

    runtime_instances_json = json.dumps(runtime_instances or [], ensure_ascii=False)
    jquery_reference_urls = ";".join(sorted(ref_urls))
    jquery_evidence_json = json.dumps(evidence, ensure_ascii=False)

    return jquery_version, runtime_version, runtime_instances_json, jquery_versions_present, jquery_multiple_present, jquery_reference_urls, jquery_evidence_json


async def process_one(net: Net, apex: str, timeout_seconds: float, max_js_bytes: int, js_concurrency: int, use_playwright: bool, headless: bool, playwright_channel: str, playwright_executable: str) -> Row:
    final_url, resolve_err = await resolve_https_443(net, apex)
    if not final_url:
        return Row(apex, "", __version__, f"ERROR: {resolve_err}", "", "[]", "", "N", "", "{}")

    (
        jquery_version,
        runtime_version,
        runtime_instances_json,
        versions_present,
        multiple_present,
        reference_urls,
        evidence_json,
    ) = await detect_for_url(net, final_url, timeout_seconds, max_js_bytes, js_concurrency, use_playwright, headless, playwright_channel, playwright_executable)

    return Row(apex, final_url, __version__, jquery_version, runtime_version, runtime_instances_json, versions_present, multiple_present, reference_urls, evidence_json)


def read_domains(path: str) -> list[str]:
    domains: list[str] = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            d = normalize_domain(line)
            if d:
                domains.append(d)
    seen = set()
    out = []
    for d in domains:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def build_timeout(args: argparse.Namespace) -> httpx.Timeout:
    return httpx.Timeout(connect=args.connect_timeout, read=args.read_timeout, write=args.write_timeout, pool=args.pool_timeout)


async def main_async(args: argparse.Namespace) -> int:
    if args.version:
        print(__version__)
        return 0

    domains = read_domains(args.input)
    if not domains:
        print("No domains found in input.", file=sys.stderr)
        return 2

    headers = {
        "User-Agent": args.user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    computed_max = args.concurrency * (2 + args.js_concurrency)
    max_connections = args.max_connections if args.max_connections else computed_max
    max_keepalive = min(max_connections, max(1, args.concurrency * 2))
    limits = httpx.Limits(max_connections=max_connections, max_keepalive_connections=max_keepalive)

    net_inflight = args.net_concurrency if args.net_concurrency else max_connections
    net_sem = asyncio.Semaphore(net_inflight)

    domain_sem = asyncio.Semaphore(args.concurrency)

    done_lock = asyncio.Lock()
    done_count = 0
    total = len(domains)

    timeout_cfg = build_timeout(args)

    async with httpx.AsyncClient(headers=headers, verify=True, limits=limits, timeout=timeout_cfg) as client:
        net = Net(client=client, sem=net_sem, timeout=timeout_cfg, retries=args.retries)

        async def bounded(apex: str) -> Row:
            nonlocal done_count
            async with domain_sem:
                row = await process_one(net, apex, args.timeout, args.max_js_bytes, args.js_concurrency, args.playwright, not args.show_browser, args.playwright_channel, args.playwright_executable)

            if not args.quiet:
                async with done_lock:
                    done_count += 1
                    print(f"[{done_count}/{total}] completed {apex}", file=sys.stderr, flush=True)
            return row

        rows = await asyncio.gather(*[asyncio.create_task(bounded(d)) for d in domains])

    with open(args.output, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "naked_domain",
            "resolving_endpoint",
            "script_version",
            "jquery_version",
            "jquery_runtime_version",
            "jquery_runtime_instances",
            "jquery_versions_present",
            "jquery_multiple_present",
            "jquery_reference_urls",
            "jquery_evidence",
        ])
        for r in rows:
            w.writerow([
                r.naked_domain,
                r.resolving_endpoint,
                r.script_version,
                r.jquery_version,
                r.jquery_runtime_version,
                r.jquery_runtime_instances,
                r.jquery_versions_present,
                r.jquery_multiple_present,
                r.jquery_reference_urls,
                r.jquery_evidence,
            ])

    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Resolve domains and detect jQuery presence")
    p.add_argument("--version", action="store_true", help="Print script version and exit")
    p.add_argument("-i", "--input", help="Input file with domains/URLs (one per line)")
    p.add_argument("-o", "--output", default="jquery_versions.csv", help="Output CSV path")
    p.add_argument("-c", "--concurrency", type=int, default=10, help="Concurrent domain workers")

    p.add_argument("-t", "--timeout", type=float, default=30.0, help="Playwright navigation timeout seconds")

    p.add_argument("--connect-timeout", type=float, default=15.0, help="httpx connect timeout seconds")
    p.add_argument("--read-timeout", type=float, default=30.0, help="httpx read timeout seconds")
    p.add_argument("--write-timeout", type=float, default=15.0, help="httpx write timeout seconds")
    p.add_argument("--pool-timeout", type=float, default=60.0, help="httpx pool timeout seconds")

    p.add_argument("--retries", type=int, default=2, help="Retries for PoolTimeout/ConnectTimeout/ReadTimeout/WriteTimeout")

    p.add_argument("--playwright", action="store_true", help="Use Playwright runtime evaluation")
    p.add_argument("--playwright-channel", default=os.environ.get("PLAYWRIGHT_CHANNEL", ""), help="Playwright channel (chrome/msedge/etc.)")
    p.add_argument("--playwright-executable", default=os.environ.get("PLAYWRIGHT_EXECUTABLE", ""), help="Playwright executable_path")
    p.add_argument("--show-browser", action="store_true", help="Run Playwright headed")

    p.add_argument("--max-js-bytes", type=int, default=2_000_000, help="Max bytes to download from each JS file")
    p.add_argument("--js-concurrency", type=int, default=2, help="Concurrent JS downloads per domain")

    p.add_argument("--max-connections", type=int, default=0, help="Override httpx max_connections (0 = computed)")
    p.add_argument("--net-concurrency", type=int, default=0, help="Cap total in-flight httpx requests (0 = equals max_connections)")

    p.add_argument("--quiet", action="store_true", help="Disable progress output")

    p.add_argument(
        "--user-agent",
        default=os.environ.get(
            "JQUERY_CHECK_UA",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        ),
        help="User-Agent header",
    )

    args = p.parse_args(argv)
    if not args.version and not args.input:
        p.error("-i/--input is required unless --version is used")
    return args


def main() -> int:
    args = parse_args(sys.argv[1:])
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    raise SystemExit(main())
