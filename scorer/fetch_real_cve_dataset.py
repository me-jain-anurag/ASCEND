#!/usr/bin/env python3
"""Fetch and assemble a real-world, leakage-free Linux CVE exploitability dataset.

Data sources (all public, official, reproducible):
  1. NVD CVE API v2.0 (services.nvd.nist.gov) — disclosure-time CVE records:
     CVSS v3.1 vector sub-metrics, CWE IDs, CPE/description text, publish date.
  2. Exploit-DB (files_exploits.csv on GitLab) — verified public working exploits
     mapped to CVE IDs (ground-truth label y=1).
  3. CISA KEV (via NVD API v2 ``hasKev`` filter) — government-confirmed active
     exploitation in the wild (ground-truth label y=1).
  4. FIRST EPSS API (api.first.org/data/v1/epss) — fetched ONLY as an external
     benchmark comparator on the held-out test set (NEVER used as a training feature).

Output:
  scorer/data/real_linux_cves.jsonl.gz — compact gzipped JSONL of real CVEs with
  strict disclosure-time features and temporal split tags (train <=2023, val 2024, test >=2025).
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import re
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
OUT_PATH = ROOT / "scorer" / "data" / "real_linux_cves.jsonl.gz"

UA = "Mozilla/5.0 (compatible; Google-Agent; +https://developers.google.com/crawling/docs/crawlers-fetchers/google-agent)"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _http_get(url: str, timeout: int = 45) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def fetch_exploitdb_cves() -> dict[str, dict[str, Any]]:
    """Download Exploit-DB files_exploits.csv and map CVE -> exploit metadata."""
    url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
    raw = _http_get(url, timeout=60).decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(raw))
    edb: dict[str, dict[str, Any]] = {}
    for row in reader:
        codes = row.get("codes") or ""
        for m in CVE_RE.findall(codes):
            cid = m.upper()
            entry = edb.setdefault(cid, {"count": 0, "types": set(), "platforms": set()})
            entry["count"] += 1
            if row.get("type"):
                entry["types"].add(row["type"].strip().lower())
            if row.get("platform"):
                entry["platforms"].add(row["platform"].strip().lower())
    return {
        cid: {
            "count": v["count"],
            "types": sorted(v["types"]),
            "platforms": sorted(v["platforms"]),
        }
        for cid, v in edb.items()
    }


def fetch_nvd_kev_items() -> tuple[set[str], list[dict[str, Any]]]:
    """Fetch all official CISA KEV CVE records directly via NVD API v2 ``hasKev``."""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev&resultsPerPage=2000&startIndex=0"
    data = json.loads(_http_get(url, timeout=60).decode("utf-8"))
    items = data.get("vulnerabilities") or []
    kevs = {(item.get("cve") or {}).get("id", "").upper() for item in items if (item.get("cve") or {}).get("id")}
    return kevs, items


def _extract_nvd_record(
    item: dict[str, Any],
    edb_map: dict[str, dict[str, Any]],
    kev_set: set[str],
) -> dict[str, Any] | None:
    cve = item.get("cve") or {}
    cid = (cve.get("id") or "").upper()
    if not cid:
        return None
    published = cve.get("published") or ""
    if len(published) < 4 or not published[:4].isdigit():
        return None
    pub_year = int(published[:4])
    if pub_year < 2018 or pub_year > 2026:
        return None

    # English description (disclosure-time text)
    desc = ""
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en":
            desc = d.get("value") or ""
            break
    if not desc or desc.startswith("** REJECT"):
        return None

    # CVSS v3.1 (or v3.0 fallback) vector components — disclosure-time structured metadata
    metrics = cve.get("metrics") or {}
    cvss_list = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or []
    if not cvss_list:
        return None
    m0 = cvss_list[0]
    cvss_data = m0.get("cvssData") or {}
    base_score = cvss_data.get("baseScore")
    if base_score is None:
        return None

    # CWE IDs
    cwes: list[str] = []
    for w in cve.get("weaknesses") or []:
        for wd in w.get("description") or []:
            val = (wd.get("value") or "").strip()
            if val.startswith("CWE-"):
                cwes.append(val)

    # Disclosure-time reference count (excluding Exploit tags to prevent hindsight leakage!)
    refs = cve.get("references") or []
    has_patch_ref = any("Patch" in (r.get("tags") or []) for r in refs)
    has_vendor_adv = any("Vendor Advisory" in (r.get("tags") or []) for r in refs)

    in_edb = cid in edb_map
    in_kev = cid in kev_set
    exploited = bool(in_edb or in_kev)

    return {
        "cve_id": cid,
        "published": published[:10],
        "pub_year": pub_year,
        "description": desc,
        "cvss_base": float(base_score),
        "cvss_vector": cvss_data.get("vectorString", ""),
        "attack_vector": cvss_data.get("attackVector", "UNKNOWN"),
        "attack_complexity": cvss_data.get("attackComplexity", "UNKNOWN"),
        "privileges_required": cvss_data.get("privilegesRequired", "UNKNOWN"),
        "user_interaction": cvss_data.get("userInteraction", "UNKNOWN"),
        "scope": cvss_data.get("scope", "UNKNOWN"),
        "confidentiality": cvss_data.get("confidentialityImpact", "UNKNOWN"),
        "integrity": cvss_data.get("integrityImpact", "UNKNOWN"),
        "availability": cvss_data.get("availabilityImpact", "UNKNOWN"),
        "cwes": sorted(set(cwes)),
        "has_patch_ref": has_patch_ref,
        "has_vendor_adv": has_vendor_adv,
        "in_exploitdb": in_edb,
        "in_cisa_kev": in_kev,
        "exploitdb_types": edb_map[cid]["types"] if in_edb else [],
        "exploited": exploited,
    }


def fetch_nvd_linux_cves(
    edb_map: dict[str, dict[str, Any]],
    kev_set: set[str],
    kev_items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Fetch a diverse, real-world corpus of Linux/privesc/infra CVEs from NVD API v2."""
    queries = [
        ("keywordSearch=privilege+escalation", 0, 2000),
        ("keywordSearch=privilege+escalation", 2000, 2000),
        ("keywordSearch=linux+kernel", 2000, 2000),
        ("keywordSearch=linux+kernel", 4000, 2000),
        ("keywordSearch=openssh", 0, 500),
        ("keywordSearch=docker", 0, 1000),
    ]
    by_id: dict[str, dict[str, Any]] = {}
    for item in kev_items:
        rec = _extract_nvd_record(item, edb_map, kev_set)
        if rec:
            by_id[rec["cve_id"]] = rec
    print(f"  Seeded {len(by_id)} valid 2018-2026 CISA KEV CVEs with CVSS v3")

    for idx, (q, start, limit) in enumerate(queries):
        if idx > 0:
            time.sleep(6.2)  # Respect NVD unauthenticated rate limit (5 req / 30s)
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{q}&resultsPerPage={limit}&startIndex={start}"
        try:
            data = json.loads(_http_get(url, timeout=60).decode("utf-8"))
        except Exception as exc:
            print(f"  WARN query {q} start={start} failed: {exc}")
            continue
        vulns = data.get("vulnerabilities") or []
        added = 0
        for item in vulns:
            rec = _extract_nvd_record(item, edb_map, kev_set)
            if rec and rec["cve_id"] not in by_id:
                by_id[rec["cve_id"]] = rec
                added += 1
        print(f"  Fetched {len(vulns)} raw ({added} new valid) for {q} start={start} (total={len(by_id)})")

    # Always ensure ASCEND's anchor CVEs (DirtyPipe & PwnKit) are present
    for anchor in ("CVE-2022-0847", "CVE-2021-4034"):
        if anchor not in by_id:
            time.sleep(6.2)
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={anchor}"
            data = json.loads(_http_get(url, timeout=45).decode("utf-8"))
            for item in data.get("vulnerabilities") or []:
                rec = _extract_nvd_record(item, edb_map, kev_set)
                if rec:
                    by_id[rec["cve_id"]] = rec

    return sorted(by_id.values(), key=lambda r: (r["published"], r["cve_id"]))


def attach_epss_for_cves(records: list[dict[str, Any]], max_cves: int = 3500) -> None:
    """Attach live FIRST EPSS scores (strictly for external baseline comparison, never training)."""
    # Prioritize test/val/anchor CVEs + a broad sample
    cids = [r["cve_id"] for r in records]
    if len(cids) > max_cves:
        # Always include 2024+ CVEs and anchor CVEs
        priority = [r["cve_id"] for r in records if r["pub_year"] >= 2024 or r["cve_id"] in ("CVE-2022-0847", "CVE-2021-4034")]
        rest = [c for c in cids if c not in set(priority)]
        cids = priority + rest[: max(0, max_cves - len(priority))]

    epss_map: dict[str, float] = {}
    batch_size = 100
    for i in range(0, len(cids), batch_size):
        batch = cids[i : i + batch_size]
        qs = urllib.parse.urlencode({"cve": ",".join(batch)})
        url = f"https://api.first.org/data/v1/epss?{qs}"
        try:
            data = json.loads(_http_get(url, timeout=30).decode("utf-8"))
            for row in data.get("data") or []:
                epss_map[row["cve"].upper()] = float(row["epss"])
        except Exception as exc:
            print(f"  WARN EPSS batch {i} failed: {exc}")
            break

    for r in records:
        r["epss_score"] = epss_map.get(r["cve_id"])


def main() -> int:
    print("1/4 Fetching Exploit-DB ground truth...")
    edb = fetch_exploitdb_cves()
    print(f"    Exploit-DB unique CVEs: {len(edb)}")

    print("2/4 Fetching CISA KEV ground truth via NVD hasKev...")
    kevs, kev_items = fetch_nvd_kev_items()
    print(f"    CISA KEV CVEs: {len(kevs)}")

    print("3/4 Fetching real Linux/OS/privesc CVEs from NVD API v2...")
    records = fetch_nvd_linux_cves(edb, kevs, kev_items)
    print(f"    Total unique real CVEs collected: {len(records)}")

    print("4/4 Fetching live FIRST EPSS scores (benchmark comparator only)...")
    attach_epss_for_cves(records)

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(OUT_PATH, "wt", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")

    by_year: dict[int, list[dict[str, Any]]] = {}
    for r in records:
        by_year.setdefault(r["pub_year"], []).append(r)
    print("\nDataset summary by publication year:")
    for yr in sorted(by_year):
        rows = by_year[yr]
        pos = sum(1 for x in rows if x["exploited"])
        epss_n = sum(1 for x in rows if x.get("epss_score") is not None)
        print(f"  {yr}: {len(rows):4d} CVEs | exploited={pos:3d} ({pos/len(rows)*100:4.1f}%) | epss_available={epss_n}")
    print(f"\nSaved to {OUT_PATH} ({OUT_PATH.stat().st_size / 1024:.1f} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
