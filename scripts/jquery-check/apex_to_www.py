#!/usr/bin/env python3
import argparse
import asyncio
import csv
import os
import sys
import time
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlparse

import httpx
import truststore

truststore.inject_into_ssl()


@dataclass
class Result:
    input_value: str
    apex_host: str

    apex_url: str
    apex_final_url: str
    apex_status_code: Optional[int]
    apex_error: str
    apex_redirect_chain: str

    www_url: str
    www_final_url: str
    www_status_code: Optional[int]
    www_error: str

    action: str  # redirects_to_www | does_not_redirect_to_www | apex_unreachable_www_ok | apex_unreachable_www_failed


def normalize_input_to_host(value: str) -> str:
    v = value.strip()
    if not v:
        return ""
    if "://" not in v:
        v = "https://" + v
    p = urlparse(v)
    return (p.hostname or "").strip().lower()


def apex_from_host(host: str) -> str:
    return host[4:] if host.startswith("www.") else host


def chain_string(history: List[httpx.Response], final: httpx.Response) -> str:
    parts = [f"{r.status_code} {str(r.url)}" for r in history]
    parts.append(f"{final.status_code} {str(final.url)}")
    return " -> ".join(parts)


def is_apex_to_www(apex_host: str, final_url: str) -> bool:
    www_host = "www." + apex_host
    final_host = (urlparse(final_url).hostname or "").lower()
    return final_host == www_host


async def fetch_follow(client: httpx.AsyncClient, url: str, timeout: float) -> httpx.Response:
    return await client.get(url, follow_redirects=True, timeout=timeout)


async def check_one(client: httpx.AsyncClient, input_value: str, timeout: float) -> Result:
    host = normalize_input_to_host(input_value)
    if not host:
        return Result(
            input_value=input_value.strip(),
            apex_host="",
            apex_url="",
            apex_final_url="",
            apex_status_code=None,
            apex_error="empty/invalid input",
            apex_redirect_chain="",
            www_url="",
            www_final_url="",
            www_status_code=None,
            www_error="",
            action="apex_unreachable_www_failed",
        )

    apex_host = apex_from_host(host)
    apex_url = f"https://{apex_host}/"
    www_url = f"https://www.{apex_host}/"

    try:
        r = await fetch_follow(client, apex_url, timeout)
        apex_final_url = str(r.url)
        apex_status = r.status_code
        apex_chain = chain_string(r.history, r)

        action = "redirects_to_www" if is_apex_to_www(apex_host, apex_final_url) else "does_not_redirect_to_www"

        return Result(
            input_value=input_value.strip(),
            apex_host=apex_host,
            apex_url=apex_url,
            apex_final_url=apex_final_url,
            apex_status_code=apex_status,
            apex_error="",
            apex_redirect_chain=apex_chain,
            www_url=www_url,
            www_final_url="",
            www_status_code=None,
            www_error="",
            action=action,
        )

    except Exception as e:
        apex_err = str(e)

        try:
            r2 = await fetch_follow(client, www_url, timeout)
            www_final_url = str(r2.url)
            www_status = r2.status_code
            www_err = ""
            action = "apex_unreachable_www_ok"
        except Exception as e2:
            www_final_url = ""
            www_status = None
            www_err = str(e2)
            action = "apex_unreachable_www_failed"

        return Result(
            input_value=input_value.strip(),
            apex_host=apex_host,
            apex_url=apex_url,
            apex_final_url="",
            apex_status_code=None,
            apex_error=apex_err,
            apex_redirect_chain="",
            www_url=www_url,
            www_final_url=www_final_url,
            www_status_code=www_status,
            www_error=www_err,
            action=action,
        )


def progress_line(done: int, total: int, r: Result, counts: dict, elapsed_s: float) -> str:
    host = r.apex_host or r.input_value
    final = r.apex_final_url or r.www_final_url
    final_part = f" final={final}" if final else ""
    return (
        f"[{done}/{total}] {host} -> {r.action}{final_part} | "
        f"redirects={counts['redirects_to_www']} "
        f"apex_unreachable_www_ok={counts['apex_unreachable_www_ok']} "
        f"errors={counts['apex_unreachable_www_failed']} "
        f"elapsed={elapsed_s:.1f}s"
    )


async def main():
    ap = argparse.ArgumentParser(description="Detect apex (naked) -> www behavior over HTTPS (443 only).")
    ap.add_argument("input_file", help="Text file with one domain or URL per line")
    ap.add_argument("--out", default="apex_www_443_report.csv", help="Output CSV filename")
    ap.add_argument("--concurrency", type=int, default=20, help="Concurrent checks")
    ap.add_argument("--timeout", type=float, default=20.0, help="Request timeout (seconds)")
    ap.add_argument("--progress", action="store_true", help="Print progress while running")
    args = ap.parse_args()

    with open(args.input_file, "r", encoding="utf-8") as f:
        inputs = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    total = len(inputs)
    results: List[Result] = []

    counts = {
        "redirects_to_www": 0,
        "does_not_redirect_to_www": 0,
        "apex_unreachable_www_ok": 0,
        "apex_unreachable_www_failed": 0,
    }

    limits = httpx.Limits(max_connections=args.concurrency, max_keepalive_connections=args.concurrency)
    headers = {"User-Agent": "apex-to-www-audit/1.0"}

    sem = asyncio.Semaphore(args.concurrency)
    start = time.time()

    async with httpx.AsyncClient(limits=limits, headers=headers) as client:
        async def bounded_check(v: str) -> Result:
            async with sem:
                return await check_one(client, v, args.timeout)

        tasks = [asyncio.create_task(bounded_check(v)) for v in inputs]

        done = 0
        for t in asyncio.as_completed(tasks):
            r = await t
            results.append(r)

            if r.action in counts:
                counts[r.action] += 1

            done += 1
            if args.progress:
                elapsed = time.time() - start
                print(progress_line(done, total, r, counts, elapsed), flush=True)

    out_path = os.path.abspath(args.out)
    print(f"Writing CSV to: {out_path}", flush=True)

    fieldnames = [
        "input",
        "apex_host",
        "apex_url",
        "apex_status_code",
        "apex_final_url",
        "apex_redirect_chain",
        "apex_error",
        "www_url",
        "www_status_code",
        "www_final_url",
        "www_error",
        "action",
    ]

    tmp_path = out_path + ".tmp"
    with open(tmp_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in results:
            w.writerow(
                {
                    "input": r.input_value,
                    "apex_host": r.apex_host,
                    "apex_url": r.apex_url,
                    "apex_status_code": r.apex_status_code if r.apex_status_code is not None else "",
                    "apex_final_url": r.apex_final_url,
                    "apex_redirect_chain": r.apex_redirect_chain,
                    "apex_error": r.apex_error,
                    "www_url": r.www_url,
                    "www_status_code": r.www_status_code if r.www_status_code is not None else "",
                    "www_final_url": r.www_final_url,
                    "www_error": r.www_error,
                    "action": r.action,
                }
            )

    os.replace(tmp_path, out_path)


if __name__ == "__main__":
    asyncio.run(main())
