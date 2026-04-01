"""
Daily IOC Puller
Consolidates IOCs from ThreatFox, MalwareBazaar, AlienVault OTX, and URLhaus
"""

import os
import requests
from datetime import datetime, timezone, timedelta
from collections import defaultdict

NOW = datetime.now(timezone.utc)
YESTERDAY = NOW - timedelta(hours=24)

# Load API keys from environment variables
ABUSECH_AUTH_KEY = os.getenv("ABUSECH_AUTH_KEY", "").strip()
OTX_API_KEY = os.getenv("OTX_API_KEY", "").strip()

HEADERS_OTX = {"X-OTX-API-KEY": OTX_API_KEY} if OTX_API_KEY else {}


def normalize_name(name: str) -> str:
    return (name or "unknown").lower().strip()


def _warn_http(prefix: str, method: str, url: str, exc: Exception) -> None:
    msg = f"  [WARN] {method} failed: {exc}"
    if "401" in str(exc) and "abuse.ch" in url:
        msg += " (abuse.ch APIs require ABUSECH_AUTH_KEY)"
    print(msg)


def safe_get(url: str, *, headers=None, params=None, timeout: int = 20):
    try:
        r = requests.get(url, headers=headers, params=params, timeout=timeout)
        r.raise_for_status()
        ct = (r.headers.get("content-type") or "").lower()
        if "application/json" in ct:
            return r.json()
        try:
            return r.json()
        except Exception:
            return {"_raw": r.text}
    except Exception as e:
        _warn_http("", "GET", url, e)
        return {}


def safe_post(url: str, payload: dict, *, headers=None, timeout: int = 20, use_form_data: bool = False):
    """POST request - JSON by default, form-encoded if use_form_data=True."""
    try:
        if use_form_data:
            r = requests.post(url, data=payload, headers=headers, timeout=timeout)
        else:
            r = requests.post(url, json=payload, headers=headers, timeout=timeout)
        r.raise_for_status()
        ct = (r.headers.get("content-type") or "").lower()
        if "application/json" in ct:
            return r.json()
        try:
            return r.json()
        except Exception:
            return {"_raw": r.text}
    except Exception as e:
        _warn_http("", "POST", url, e)
        return {}


def abusech_headers() -> dict:
    return {"Auth-Key": ABUSECH_AUTH_KEY} if ABUSECH_AUTH_KEY else {}


def is_recent(date_str: str) -> bool:
    if not date_str:
        return False
    try:
        dt = datetime.strptime(date_str[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        return dt >= YESTERDAY
    except Exception:
        try:
            dt = datetime.strptime(date_str[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
            return dt >= YESTERDAY
        except Exception:
            return True


def empty_record():
    return {
        "record_number":       "",
        "malware_name":        "",
        "one_line_summary":    "",
        "indicator_value":     set(),
        "indicator_type":      set(),
        "last_detect_time":    "",
        "cve":                 set(),
        "ip_subnet_asn":       set(),
        "url_domain":          set(),
        "hash_value":          set(),
        "virus_total_count":   "",
        "ioc_types":           set(),
        "confidence":          "",
        "threat_actor_type":   set(),
        "threat_origin":       set(),
        "threat_operations":   set(),
        "location":            set(),
        "target_location":     set(),
        "source_of_detection": set(),
        "reporter_name":       set(),
        "file_name":           set(),
        "file_path":           set(),
        "file_type":           set(),
    }


# ── SOURCES ───────────────────────────────────────────────────────────────────

def pull_threatfox(merged):
    """Pull IOCs from ThreatFox (abuse.ch)."""
    print("Pulling ThreatFox...")
    try:
        data = safe_post(
            "https://threatfox-api.abuse.ch/api/v1/",
            {"query": "get_iocs", "days": 1},
            headers=abusech_headers(),
        )
        count = 0
        entries = data.get("data") or []
        if not isinstance(entries, list):
            print(f"   -> 0 entries (unexpected response format)")
            return 0
        
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            
            name = normalize_name(entry.get("malware", "unknown"))
            r = merged[name]
            if not r["malware_name"]:
                r["malware_name"] = entry.get("malware") or name

            ioc_val = str(entry.get("ioc") or "").strip()
            ioc_type = str(entry.get("ioc_type_desc") or "").strip()
            
            if ioc_val:
                r["indicator_value"].add(ioc_val)
            if ioc_type:
                r["indicator_type"].add(ioc_type)
                r["ioc_types"].add(ioc_type)

            ioc_type_lower = ioc_type.lower()
            if "ip" in ioc_type_lower:
                r["ip_subnet_asn"].add(ioc_val)
            elif "url" in ioc_type_lower or "domain" in ioc_type_lower:
                r["url_domain"].add(ioc_val)
            elif any(x in ioc_type_lower for x in ["hash", "md5", "sha"]):
                r["hash_value"].add(ioc_val)

            tags = entry.get("tags")
            if isinstance(tags, list):
                for t in tags:
                    if isinstance(t, str) and t.lower().startswith("cve-"):
                        r["cve"].add(t)

            conf = entry.get("confidence_level")
            if conf and not r["confidence"]:
                r["confidence"] = f"{conf}%"

            ts = str(entry.get("first_seen") or "").strip()
            if ts and not r["last_detect_time"]:
                r["last_detect_time"] = ts[:16]

            threat = str(entry.get("threat_type_desc") or "").strip()
            if threat:
                r["threat_actor_type"].add(threat)

            r["source_of_detection"].add("ThreatFox")
            r["reporter_name"].add("abuse.ch")
            count += 1

        print(f"   -> {count} entries")
        return count
    except Exception as e:
        print(f"   -> 0 entries (error: {e})")
        return 0


def pull_malwarebazaar(merged):
    """Pull recent malware samples from MalwareBazaar (abuse.ch)."""
    print("Pulling MalwareBazaar...")
    try:
        data = safe_post(
            "https://mb-api.abuse.ch/api/v1/",
            {"query": "get_recent", "selector": "time"},
            headers=abusech_headers(),
            use_form_data=True,  # MalwareBazaar requires form-encoded POST
        )
        count = 0
        entries = data.get("data") or []
        if not isinstance(entries, list):
            print(f"   -> 0 entries (unexpected response format)")
            return 0
        
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            
            if not is_recent(entry.get("first_seen", "")):
                continue
            
            tags = entry.get("tags")
            if not isinstance(tags, list):
                tags = []
            
            sig = entry.get("signature")
            if not sig and tags:
                sig = tags[0] if isinstance(tags[0], str) else "unknown"
            elif not sig:
                sig = "unknown"
            
            name = normalize_name(sig)
            r = merged[name]
            if not r["malware_name"]:
                r["malware_name"] = sig

            for h in [entry.get("sha256_hash"), entry.get("md5_hash"), entry.get("sha1_hash")]:
                if h and isinstance(h, str):
                    r["hash_value"].add(h)
                    r["indicator_value"].add(h)
                    r["indicator_type"].add("Hash")
                    r["ioc_types"].add("Hash")

            fname = entry.get("file_name")
            if fname and isinstance(fname, str):
                r["file_name"].add(fname)
            ftype = entry.get("file_type")
            if ftype and isinstance(ftype, str):
                r["file_type"].add(ftype)

            for t in tags:
                if isinstance(t, str) and t.lower().startswith("cve-"):
                    r["cve"].add(t)

            ts = str(entry.get("first_seen") or "").strip()
            if ts and not r["last_detect_time"]:
                r["last_detect_time"] = ts[:16]

            r["source_of_detection"].add("MalwareBazaar")
            r["reporter_name"].add("abuse.ch")
            count += 1

        print(f"   -> {count} entries")
        return count
    except Exception as e:
        print(f"   -> 0 entries (error: {e})")
        return 0


def pull_otx(merged):
    """Pull threat intel pulses from AlienVault OTX."""
    if not OTX_API_KEY:
        print("Pulling AlienVault OTX... (skipped: set OTX_API_KEY)")
        return 0
    print("Pulling AlienVault OTX...")
    try:
        since = YESTERDAY.strftime("%Y-%m-%dT%H:%M:%S")
        data = safe_get(
            f"https://otx.alienvault.com/api/v1/pulses/subscribed?modified_since={since}&limit=50",
            headers=HEADERS_OTX,
        )
        count = 0
        results = data.get("results") or []
        if not isinstance(results, list):
            print(f"   -> 0 pulses (unexpected response format)")
            return 0
        
        for pulse in results:
            if not isinstance(pulse, dict):
                continue
            
            families = pulse.get("malware_families")
            display = None
            
            if isinstance(families, list) and families:
                first_fam = families[0]
                if isinstance(first_fam, dict):
                    display = first_fam.get("display_name") or first_fam.get("name")
                elif isinstance(first_fam, str):
                    display = first_fam
            
            if not display:
                display = pulse.get("name") or "unknown"
            
            name = normalize_name(display)
            r = merged[name]
            if not r["malware_name"]:
                r["malware_name"] = display

            desc = pulse.get("description")
            if isinstance(desc, str) and desc.strip() and not r["one_line_summary"]:
                r["one_line_summary"] = desc[:120].replace("\n", " ")

            actor = pulse.get("adversary")
            if isinstance(actor, str) and actor:
                r["threat_actor_type"].add(actor)

            targeted = pulse.get("targeted_countries")
            if isinstance(targeted, list):
                for c in targeted:
                    if isinstance(c, str):
                        r["target_location"].add(c)
            
            industries = pulse.get("industries")
            if isinstance(industries, list):
                for ind in industries:
                    if isinstance(ind, str):
                        r["threat_operations"].add(ind)
            
            tags = pulse.get("tags")
            if isinstance(tags, list):
                for tag in tags:
                    if isinstance(tag, str) and tag.lower().startswith("cve-"):
                        r["cve"].add(tag)

            indicators = pulse.get("indicators")
            if isinstance(indicators, list):
                for ind in indicators:
                    if not isinstance(ind, dict):
                        continue
                    itype = str(ind.get("type") or "").strip()
                    ival = str(ind.get("indicator") or "").strip()
                    if not ival:
                        continue
                    r["indicator_value"].add(ival)
                    r["indicator_type"].add(itype)
                    r["ioc_types"].add(itype)
                    if itype in ("IPv4", "IPv6", "CIDR"):
                        r["ip_subnet_asn"].add(ival)
                    elif itype in ("URL", "domain", "hostname"):
                        r["url_domain"].add(ival)
                    elif "hash" in itype.lower():
                        r["hash_value"].add(ival)
                    elif itype == "CVE":
                        r["cve"].add(ival)

            ts = pulse.get("modified")
            if isinstance(ts, str) and ts and not r["last_detect_time"]:
                r["last_detect_time"] = ts[:16]

            r["source_of_detection"].add("AlienVault OTX")
            author = pulse.get("author_name")
            r["reporter_name"].add(author if isinstance(author, str) and author else "OTX Community")
            count += 1

        print(f"   -> {count} pulses")
        return count
    except Exception as e:
        print(f"   -> 0 pulses (error: {e})")
        return 0


def pull_urlhaus(merged):
    """Pull recent malicious URLs from URLhaus (abuse.ch)."""
    print("Pulling URLhaus...")
    try:
        data = safe_get(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/",
            headers=abusech_headers(),
        )
        count = 0
        urls = data.get("urls") or []
        if not isinstance(urls, list):
            print(f"   -> 0 entries (unexpected response format)")
            return 0
        
        for entry in urls:
            if not isinstance(entry, dict):
                continue
            
            if not is_recent(entry.get("date_added", "")):
                continue
            
            tags = entry.get("tags")
            if not isinstance(tags, list):
                tags = []
            
            tag_name = None
            for t in tags:
                if isinstance(t, str) and t.strip():
                    tag_name = t.strip()
                    break
            
            name = normalize_name(tag_name or "malware-url")
            r = merged[name]
            if not r["malware_name"]:
                r["malware_name"] = tag_name or "Malware URL"

            url_val = str(entry.get("url") or "").strip()
            if url_val:
                r["url_domain"].add(url_val)
                r["indicator_value"].add(url_val)
                r["indicator_type"].add("URL")
                r["ioc_types"].add("URL")

            ts = str(entry.get("date_added") or "").strip()
            if ts and not r["last_detect_time"]:
                r["last_detect_time"] = ts[:16]

            r["source_of_detection"].add("URLhaus")
            r["reporter_name"].add("abuse.ch")
            count += 1

        print(f"   -> {count} entries")
        return count
    except Exception as e:
        print(f"   -> 0 entries (error: {e})")
        return 0


# ── TERMINAL OUTPUT ───────────────────────────────────────────────────────────

def extract_domain(url: str) -> str:
    """Extract domain from URL."""
    if not url or not isinstance(url, str):
        return ""
    url = url.strip()
    if url.startswith("http://"):
        url = url[7:]
    elif url.startswith("https://"):
        url = url[8:]
    if len(url) < 3:
        return url
    parts = url.split("/")[0].split(":")
    return parts[0] if parts else url


def print_ioc_sheet(rows, *, search_filter: str = None):
    """Print IOCs in office-sheet format."""
    rows = list(rows)
    
    if search_filter:
        search_filter = search_filter.lower()
        rows = [r for r in rows if search_filter in (r.get("malware_name") or "").lower()]
    
    print(f"\n{'='*80}")
    print(f"  IOC REPORT  |  {NOW.strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"  Window: Last 24 hours  |  Families: {len(rows)}")
    print(f"{'='*80}")
    
    if not rows:
        print("\nNo results found.")
        if search_filter:
            print(f"(Filter was: '{search_filter}')")
        return
    
    for idx, r in enumerate(rows, 1):
        name = (r.get("malware_name") or "unknown").strip()
        last_seen = (r.get("last_detect_time") or "").strip()
        sources = (r.get("source_of_detection") or "").strip()
        confidence = (r.get("confidence") or "").strip()
        
        ips = sorted(set(x.strip() for x in (r.get("ip_subnet_asn") or "").split(" | ") if x.strip()))
        urls_raw = sorted(set(x.strip() for x in (r.get("url_domain") or "").split(" | ") if x.strip()))
        hashes = sorted(set(x.strip() for x in (r.get("hash_value") or "").split(" | ") if x.strip()))
        cves = sorted(set(x.strip() for x in (r.get("cve") or "").split(" | ") if x.strip()))
        
        domains = sorted(set(d for d in (extract_domain(u) for u in urls_raw if u) if d))
        full_urls = [u for u in urls_raw if len(u) > 10 and "/" in u[10:]]
        
        total_iocs = len(ips) + len(domains) + len(hashes)
        
        print(f"\n{'─'*80}")
        print(f"[{idx}] MALWARE: {name.upper()}")
        print(f"{'─'*80}")
        print(f"  Last Seen  : {last_seen}")
        print(f"  Sources    : {sources}")
        if confidence:
            print(f"  Confidence : {confidence}")
        print(f"  Total IOCs : {total_iocs} (IPs: {len(ips)}, Domains: {len(domains)}, Hashes: {len(hashes)})")
        if cves:
            print(f"  CVEs       : {', '.join(cves)}")
        
        if ips:
            print(f"\n  ┌─ IPs ({len(ips)}) ─────────────────────────────")
            for ip in ips:
                print(f"  │ {ip}")
            print(f"  └{'─'*45}")
        
        if domains:
            print(f"\n  ┌─ Domains ({len(domains)}) ─────────────────────────────")
            for d in domains:
                print(f"  │ {d}")
            print(f"  └{'─'*45}")
        
        if full_urls and len(full_urls) <= 20:
            print(f"\n  ┌─ Full URLs ({len(full_urls)}) ─────────────────────────────")
            for u in full_urls[:20]:
                print(f"  │ {u}")
            if len(full_urls) > 20:
                print(f"  │ ... and {len(full_urls)-20} more")
            print(f"  └{'─'*45}")
        elif full_urls:
            print(f"\n  ┌─ Full URLs ({len(full_urls)} total - showing first 20) ────")
            for u in full_urls[:20]:
                print(f"  │ {u}")
            print(f"  │ ... and {len(full_urls)-20} more")
            print(f"  └{'─'*45}")
        
        if hashes:
            print(f"\n  ┌─ Hashes ({len(hashes)}) ─────────────────────────────")
            for h in hashes:
                print(f"  │ {h}")
            print(f"  └{'─'*45}")
    
    print(f"\n{'='*80}")
    print(f"  END OF REPORT  |  {len(rows)} malware families")
    print(f"{'='*80}\n")


def print_quick_summary(rows):
    """Print quick summary table."""
    rows = list(rows)
    print(f"\n{'='*80}")
    print(f"  QUICK SUMMARY  |  {NOW.strftime('%Y-%m-%d %H:%M UTC')}  |  {len(rows)} families")
    print(f"{'='*80}")
    print(f"{'#':<4} {'Malware':<25} {'IPs':<6} {'Domains':<8} {'Hashes':<8} {'Sources'}")
    print(f"{'-'*80}")
    
    for idx, r in enumerate(rows, 1):
        name = (r.get("malware_name") or "unknown")[:24]
        sources = (r.get("source_of_detection") or "")[:20]
        
        ips = len([x for x in (r.get("ip_subnet_asn") or "").split(" | ") if x.strip()])
        domains = len([x for x in (r.get("url_domain") or "").split(" | ") if x.strip()])
        hashes = len([x for x in (r.get("hash_value") or "").split(" | ") if x.strip()])
        
        print(f"{idx:<4} {name:<25} {ips:<6} {domains:<8} {hashes:<8} {sources}")
    
    print(f"{'-'*80}\n")


# ── MAIN ──────────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Daily IOC Puller - Consolidates IOCs from multiple threat intel sources")
    parser.add_argument("--filter", "-f", help="Filter by malware name (partial match, case-insensitive)")
    parser.add_argument("--summary", "-s", action="store_true", help="Show quick summary table only")
    parser.add_argument("--list", "-l", action="store_true", help="List all malware families found")
    args = parser.parse_args()

    print(f"\n{'='*55}")
    print(f"  DAILY IOC PULLER  |  {NOW.strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"{'='*55}\n")

    if not ABUSECH_AUTH_KEY:
        print("[INFO] ABUSECH_AUTH_KEY not set → ThreatFox/MalwareBazaar/URLhaus may return 401.")
    if not OTX_API_KEY:
        print("[INFO] OTX_API_KEY not set → OTX will be skipped.")

    merged = defaultdict(empty_record)

    pull_threatfox(merged)
    pull_malwarebazaar(merged)
    pull_otx(merged)
    pull_urlhaus(merged)

    print(f"\nMerging {len(merged)} unique malware families...")

    rows = []
    for idx, (_key, record) in enumerate(sorted(merged.items()), 1):
        record["record_number"] = idx
        flat = {}
        for k, v in record.items():
            flat[k] = " | ".join(sorted(str(x) for x in v if x)) if isinstance(v, set) else v
        rows.append(flat)

    if args.list:
        print(f"\n--- Malware families found ({len(rows)}) ---")
        for r in rows:
            print(f"  • {r.get('malware_name', 'unknown')}")
        print()
    elif args.summary:
        print_quick_summary(rows)
    else:
        print_ioc_sheet(rows, search_filter=args.filter)
    
    return 0


if __name__ == "__main__":
    main()
