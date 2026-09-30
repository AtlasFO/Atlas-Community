"""IOC enrichment — VirusTotal, AbuseIPDB, OTX, urlscan, MISP, machinae.

Degrades gracefully without API keys: a lookup whose key is unset reports
that plainly instead of failing the run.

**Every provider here answers an error with a JSON body that parses
cleanly.** A rejected key, an exhausted quota and a service outage all
return a document whose `data`/`pulse_info` key is simply absent, so a
caller that reads only the payload sees an empty statistics block — which
is shaped exactly like "nothing detected this indicator". In a forensic
tool that is a false negative dressed as a clean verdict, so every request
goes through `_request_json()`, which classifies the HTTP status *before*
anything looks at the body.
"""
import base64
import json
import os
import re
import shutil
import time
from typing import Any, Optional
from fastmcp import FastMCP

mcp = FastMCP("enrichment")


def _env(var: str) -> Optional[str]:
    """Current value of an API-key variable, read at call time.

    Deliberately not captured into a module constant at import: the
    dashboard's OSINT config page writes keys into the environment while a
    process may already be running, and a constant bound at import would
    keep reporting "not configured" until restart. An empty string in .env
    counts as unset.
    """
    return (os.environ.get(var) or "").strip() or None


# Retried statuses: a throttle or a transient server fault is worth one more
# attempt, a rejected key never is.
_RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
_MAX_ATTEMPTS = 3
_MAX_SLEEP_SECONDS = 20.0


def _retry_after_seconds(resp: Any, attempt: int) -> float:
    """Honour Retry-After when the provider sends one, else back off."""
    raw = ""
    try:
        raw = (resp.headers or {}).get("Retry-After", "")
    except Exception:
        raw = ""
    try:
        # A header the provider actually sent is authoritative, including a
        # literal 0 ("retry immediately"); only its absence or an unparseable
        # value falls through to exponential backoff.
        wait = max(0.0, float(str(raw).strip()))
    except (TypeError, ValueError):
        wait = 2.0 ** attempt
    return min(wait, _MAX_SLEEP_SECONDS)


def _http_error(service: str, status: int, resp: Any) -> dict:
    """Human-readable failure for a non-2xx status, with the status kept."""
    if status in (401, 403):
        reason = (f"{service} rejected the API key (HTTP {status}). The key is "
                  f"missing, expired, or lacks access to this endpoint.")
    elif status == 429:
        reason = (f"{service} rate limit reached (HTTP 429) and still limited "
                  f"after {_MAX_ATTEMPTS} attempts. VirusTotal's public tier "
                  f"allows 4 requests/minute — space the lookups out or use a "
                  f"key with a higher quota.")
    elif status >= 500:
        reason = f"{service} is unavailable (HTTP {status})."
    else:
        reason = f"{service} returned HTTP {status}."
    detail = ""
    try:
        body = resp.json()
        if isinstance(body, dict):
            err = body.get("error")
            if isinstance(err, dict):
                detail = str(err.get("message") or err.get("code") or "")
            elif err:
                detail = str(err)
            detail = detail or str(body.get("message") or "")
    except Exception:
        detail = ""
    return {
        "success": False,
        "error": f"{reason} {detail}".strip(),
        "http_status": status,
        "service": service,
    }


def _request_json(service: str, method: str, url: str, **kwargs) -> tuple:
    """Perform one HTTP request and return ``(payload, error)``.

    Exactly one side is populated. `error` is a ready-to-return failure dict
    carrying `http_status`, so callers can special-case 404 ("indicator not
    known to this provider" — a real answer, not a failure) while every other
    non-2xx status becomes an explicit error instead of an empty payload that
    reads as "clean".
    """
    import httpx
    last = None
    for attempt in range(_MAX_ATTEMPTS):
        try:
            resp = httpx.request(method, url, **kwargs)
        except Exception as exc:  # network/DNS/TLS/timeout
            last = {"success": False, "error": f"{service} request failed: {exc}",
                    "service": service}
            if attempt + 1 < _MAX_ATTEMPTS:
                time.sleep(min(2.0 ** attempt, _MAX_SLEEP_SECONDS))
                continue
            return None, last
        status = getattr(resp, "status_code", 200)
        if status in _RETRY_STATUSES and attempt + 1 < _MAX_ATTEMPTS:
            time.sleep(_retry_after_seconds(resp, attempt))
            continue
        if status >= 400:
            return None, _http_error(service, status, resp)
        try:
            return resp.json(), None
        except Exception as exc:
            return None, {"success": False,
                          "error": f"{service} returned an unreadable body: {exc}",
                          "http_status": status, "service": service}
    return None, (last or {"success": False,
                           "error": f"{service} request failed", "service": service})

_SESSION_FILE = os.path.expanduser("~/.cache/atlas/session.json")


def _no_key(service: str) -> dict:
    return {
        "success": False,
        "error": f"{service} API key not configured. Set {service.upper().replace(' ', '_')}_API_KEY environment variable.",
    }


def _analysis_dir() -> Optional[str]:
    """Best-effort resolve the active case's analysis/ dir from the trace path.

    Order: the live execution-log singleton, then ~/.cache/atlas/session.json.
    Returns None when no case is configured, so enrichment persistence is a
    no-op outside a case (e.g. an ad-hoc lookup or a unit test).
    """
    trace_path = None
    try:
        from core.execution_log import log as _log
        trace_path = getattr(_log, "_path", None)
    except Exception:
        trace_path = None
    if not trace_path:
        try:
            with open(_SESSION_FILE) as fh:
                trace_path = (json.load(fh) or {}).get("path")
        except Exception:
            trace_path = None
    if not trace_path:
        return None
    d = os.path.dirname(os.path.abspath(trace_path))
    return d if os.path.isdir(d) else None


def _safe_name(value: str) -> str:
    """Filesystem-safe slug for an indicator (keeps it recognizable)."""
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value)).strip("_")
    return (slug or "indicator")[:120]


def _persist(kind: str, indicator: str, result: dict) -> Optional[str]:
    """Write a full enrichment result to <case>/analysis/enrichment/<kind>_<ioc>.json.

    Persisting the raw lookup (not just the summarized tool return) gives the
    attribution fusion (T2-3c) a durable, greppable source of actor/family
    signals per indicator. No-op — and never raises — when no case is
    configured. Returns the written path, or None.
    """
    base = _analysis_dir()
    if not base:
        return None
    try:
        out_dir = os.path.join(base, "enrichment")
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, f"{kind}_{_safe_name(indicator)}.json")
        with open(path, "w") as fh:
            json.dump(result, fh, indent=2, default=str)
        return path
    except Exception:
        return None


@mcp.tool()
def vt_lookup_hash(file_hash: str) -> dict:
    """
    Look up a file hash (MD5/SHA1/SHA256) on VirusTotal.
    Returns detection ratio, engine results, and file metadata.
    Requires VIRUSTOTAL_API_KEY environment variable.
    """
    key = _env("VIRUSTOTAL_API_KEY")
    if not key:
        return _no_key("VirusTotal")
    data, err = _request_json(
        "VirusTotal", "GET",
        f"https://www.virustotal.com/api/v3/files/{file_hash}",
        headers={"x-apikey": key}, timeout=30,
    )
    if err is not None:
        # 404 is an answer, not a failure: VirusTotal has never seen the file.
        if err.get("http_status") == 404:
            return {"success": True, "found": False, "hash": file_hash,
                    "message": "Not found in VirusTotal."}
        return {**err, "hash": file_hash}
    attrs = (data.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    result = {
        "success": True,
        "found": True,
        "hash": file_hash,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "undetected": stats.get("undetected", 0),
        "total_engines": sum(v for v in stats.values() if isinstance(v, int)),
        "names": (attrs.get("names") or [])[:10],
        "type_description": attrs.get("type_description"),
        "first_submission": attrs.get("first_submission_date"),
        "last_analysis_date": attrs.get("last_analysis_date"),
        "full_stats": stats,
    }
    sidecar = _persist("vt_hash", file_hash, result)
    if sidecar:
        result["sidecar_path"] = sidecar
    return result


@mcp.tool()
def vt_lookup_ip(ip_address: str) -> dict:
    """
    Look up an IP address on VirusTotal.
    Returns reputation score, country, ASN, and detection history.
    Requires VIRUSTOTAL_API_KEY environment variable.
    """
    key = _env("VIRUSTOTAL_API_KEY")
    if not key:
        return _no_key("VirusTotal")
    data, err = _request_json(
        "VirusTotal", "GET",
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}",
        headers={"x-apikey": key}, timeout=30,
    )
    if err is not None:
        if err.get("http_status") == 404:
            return {"success": True, "found": False, "ip": ip_address,
                    "message": "Not found in VirusTotal."}
        return {**err, "ip": ip_address}
    attrs = (data.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    result = {
        "success": True,
        "found": True,
        "ip": ip_address,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "country": attrs.get("country"),
        "asn": attrs.get("asn"),
        "as_owner": attrs.get("as_owner"),
        "reputation": attrs.get("reputation"),
        "tags": attrs.get("tags") or [],
        "total_engines": sum(v for v in stats.values() if isinstance(v, int)),
        "full_stats": stats,
    }
    sidecar = _persist("vt_ip", ip_address, result)
    if sidecar:
        result["sidecar_path"] = sidecar
    return result


@mcp.tool()
def vt_lookup_domain(domain: str) -> dict:
    """
    Look up a domain on VirusTotal.
    Returns detection ratio, categories, and DNS resolutions.
    Requires VIRUSTOTAL_API_KEY environment variable.
    """
    key = _env("VIRUSTOTAL_API_KEY")
    if not key:
        return _no_key("VirusTotal")
    data, err = _request_json(
        "VirusTotal", "GET",
        f"https://www.virustotal.com/api/v3/domains/{domain}",
        headers={"x-apikey": key}, timeout=30,
    )
    if err is not None:
        if err.get("http_status") == 404:
            return {"success": True, "found": False, "domain": domain,
                    "message": "Not found in VirusTotal."}
        return {**err, "domain": domain}
    attrs = (data.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    result = {
        "success": True,
        "found": True,
        "domain": domain,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "categories": attrs.get("categories") or {},
        "reputation": attrs.get("reputation"),
        "registrar": attrs.get("registrar"),
        "creation_date": attrs.get("creation_date"),
        "last_dns_records": (attrs.get("last_dns_records") or [])[:5],
        "total_engines": sum(v for v in stats.values() if isinstance(v, int)),
        "full_stats": stats,
    }
    sidecar = _persist("vt_domain", domain, result)
    if sidecar:
        result["sidecar_path"] = sidecar
    return result


@mcp.tool()
def vt_lookup_url(url: str) -> dict:
    """
    Look up a URL on VirusTotal — reputation, categories, and the final URL
    VT's own crawler landed on after following redirects, if VT has already
    scanned it. Lookup only: this never submits an unseen URL, because
    VirusTotal's public API makes a new submission visible to other VT
    users/customers — including whoever controls a live phishing link, who
    could see it show up. For a URL VT hasn't seen (a fresh shortener link),
    use urlscan_submit_scan instead — its submissions default to unlisted.
    Requires VIRUSTOTAL_API_KEY environment variable.
    """
    key = _env("VIRUSTOTAL_API_KEY")
    if not key:
        return _no_key("VirusTotal")
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    data, err = _request_json(
        "VirusTotal", "GET",
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers={"x-apikey": key}, timeout=30,
    )
    if err is not None:
        if err.get("http_status") == 404:
            return {"success": True, "found": False, "url": url,
                    "message": "Not found in VirusTotal — never scanned by "
                               "VT. Try urlscan_submit_scan for an active, "
                               "unlisted resolution."}
        return {**err, "url": url}
    attrs = (data.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    result = {
        "success": True,
        "found": True,
        "url": url,
        "final_url": attrs.get("last_final_url") or attrs.get("url"),
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "categories": attrs.get("categories") or {},
        "total_engines": sum(v for v in stats.values() if isinstance(v, int)),
        "full_stats": stats,
    }
    sidecar = _persist("vt_url", url, result)
    if sidecar:
        result["sidecar_path"] = sidecar
    return result


@mcp.tool()
def abuseipdb_check(ip_address: str, max_age_days: int = 90) -> dict:
    """
    Check an IP address against the AbuseIPDB database.
    Returns abuse confidence score, number of reports, country, and ISP.
    Requires ABUSEIPDB_API_KEY environment variable.
    """
    key = _env("ABUSEIPDB_API_KEY")
    if not key:
        return _no_key("AbuseIPDB")
    data, err = _request_json(
        "AbuseIPDB", "GET", "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": ip_address, "maxAgeInDays": max_age_days,
                "verbose": True},
        headers={"Key": key, "Accept": "application/json"}, timeout=30,
    )
    if err is not None:
        return {**err, "ip": ip_address}
    payload = data.get("data") or {}
    result = {
        "success": True,
        "ip": ip_address,
        "abuse_confidence_score": payload.get("abuseConfidenceScore"),
        "total_reports": payload.get("totalReports"),
        "country_code": payload.get("countryCode"),
        "isp": payload.get("isp"),
        "domain": payload.get("domain"),
        "is_tor": payload.get("isTor"),
        "is_whitelisted": payload.get("isWhitelisted"),
        "last_reported": payload.get("lastReportedAt"),
    }
    sidecar = _persist("abuseipdb", ip_address, result)
    if sidecar:
        result["sidecar_path"] = sidecar
    return result


@mcp.tool()
def machinae_lookup(indicator: str, indicator_type: Optional[str] = None) -> dict:
    """
    Look up an IOC (IP, domain, hash, URL) using machinae (multi-source OSINT tool).
    indicator_type: 'ipv4', 'fqdn', 'hash', 'url' — machinae auto-detects if omitted.
    machinae queries multiple free OSINT sources without requiring API keys.
    """
    if not shutil.which("machinae"):
        return {"success": False,
                "error": "machinae not installed — pip install machinae"}
    from core import run
    cmd = ["machinae", indicator]
    if indicator_type:
        cmd += ["-t", indicator_type]
    return run(cmd, timeout=60)


@mcp.tool()
def otx_lookup(indicator: str, indicator_type: str) -> dict:
    """
    Look up an indicator on AlienVault OTX.
    indicator_type: 'IPv4', 'domain', 'hostname', 'file' (hash), or 'url'.
    Returns pulse count, associated tags, and malware families.
    Requires OTX_API_KEY environment variable.
    """
    key = _env("OTX_API_KEY")
    if not key:
        return _no_key("OTX")
    section = {
        "IPv4": f"IPv4/{indicator}/general",
        "domain": f"domain/{indicator}/general",
        "hostname": f"hostname/{indicator}/general",
        "file": f"file/{indicator}/general",
        "url": f"url/{indicator}/general",
    }.get(indicator_type)
    if not section:
        return {"success": False,
                "error": f"unknown indicator_type '{indicator_type}'"}
    data, err = _request_json(
        "OTX", "GET", f"https://otx.alienvault.com/api/v1/indicators/{section}",
        headers={"X-OTX-API-KEY": key}, timeout=30,
    )
    if err is not None:
        # 404 means OTX holds nothing on this indicator — a real answer.
        if err.get("http_status") == 404:
            return {"success": True, "found": False, "indicator": indicator}
        return {**err, "indicator": indicator}
    pulses = data.get("pulse_info") or {}
    tags, families, adversaries = set(), set(), set()
    for pulse in pulses.get("pulses") or []:
        tags.update(pulse.get("tags") or [])
        families.update(pulse.get("malware_families") or [])
        # A pulse's `adversary` names the threat actor OTX attributes it to
        # (often blank) — the primary infra-to-actor signal for attribution.
        adv = pulse.get("adversary")
        if adv:
            adversaries.add(str(adv))
    result = {
        "success": True,
        "found": True,
        "indicator": indicator,
        "indicator_type": indicator_type,
        "pulse_count": pulses.get("count", 0),
        "tags": sorted(tags)[:20],
        "malware_families": sorted(str(f) for f in families)[:20],
        "adversaries": sorted(adversaries)[:20],
        "reputation": data.get("reputation"),
    }
    sidecar = _persist("otx", indicator, result)
    if sidecar:
        result["sidecar_path"] = sidecar
    return result


@mcp.tool()
def urlscan_search(query: str, size: int = 20) -> dict:
    """
    Search urlscan.io's public scan database (read-only — does not submit or
    scan any URL). query: a urlscan search string, e.g. 'domain:evil.example'
    or 'page.url:"/login"'. Requires URLSCAN_API_KEY.
    """
    key = _env("URLSCAN_API_KEY")
    if not key:
        return _no_key("URLScan")
    data, err = _request_json(
        "urlscan.io", "GET", "https://urlscan.io/api/v1/search/",
        params={"q": query, "size": min(size, 100)},
        headers={"API-Key": key}, timeout=30,
    )
    if err is not None:
        return {**err, "query": query}
    results = [{
        "url": (r.get("page") or {}).get("url"),
        "domain": (r.get("page") or {}).get("domain"),
        "ip": (r.get("page") or {}).get("ip"),
        "country": (r.get("page") or {}).get("country"),
        "time": (r.get("task") or {}).get("time"),
        "result": r.get("result"),
    } for r in data.get("results") or []]
    result = {"success": True, "query": query,
              "total": data.get("total", len(results)), "results": results}
    sidecar = _persist("urlscan", query, result)
    if sidecar:
        result["sidecar_path"] = sidecar
    return result


@mcp.tool()
def urlscan_submit_scan(url: str, visibility: str = "unlisted") -> dict:
    """
    Submit a URL to urlscan.io for a sandboxed visit. urlscan.io's own
    infrastructure visits the URL and follows every redirect (shorteners,
    phishing lures) — not Atlas's, which is what makes this the safe way to
    unwind a suspicious link instead of fetching it directly. Returns a scan
    UUID; the scan itself takes 10-40s, so fetch the result afterwards with
    urlscan_fetch_result(uuid).

    visibility: 'unlisted' (default — not searchable by other urlscan
    users) or 'private' (paid tiers only). 'public' is refused here: a
    public scan is visible to anyone, including whoever controls the URL
    under investigation.
    Requires URLSCAN_API_KEY.
    """
    key = _env("URLSCAN_API_KEY")
    if not key:
        return _no_key("URLScan")
    if visibility == "public":
        return {"success": False, "url": url, "error":
                "refusing 'public' visibility — use 'unlisted' or 'private' "
                "so the submission doesn't expose the investigation"}
    data, err = _request_json(
        "urlscan.io", "POST", "https://urlscan.io/api/v1/scan/",
        headers={"API-Key": key, "Content-Type": "application/json"},
        json={"url": url, "visibility": visibility}, timeout=30,
    )
    if err is not None:
        return {**err, "url": url}
    result = {
        "success": True,
        "url": url,
        "uuid": data.get("uuid"),
        "visibility": visibility,
        "result_page": data.get("result"),
        "message": "submitted — call urlscan_fetch_result(uuid) in 10-40s",
    }
    sidecar = _persist("urlscan_submit", url, result)
    if sidecar:
        result["sidecar_path"] = sidecar
    return result


@mcp.tool()
def urlscan_fetch_result(uuid: str) -> dict:
    """
    Fetch a scan submitted with urlscan_submit_scan. Returns the final URL
    after every redirect, the effective domain/IP/country, a malicious
    verdict and score, and a screenshot link — the actual "where does this
    link really go" answer for a shortened or obfuscated phishing URL.
    found: false (a 404) means the scan is still processing — wait and retry.
    Requires URLSCAN_API_KEY.
    """
    key = _env("URLSCAN_API_KEY")
    if not key:
        return _no_key("URLScan")
    data, err = _request_json(
        "urlscan.io", "GET", f"https://urlscan.io/api/v1/result/{uuid}/",
        headers={"API-Key": key}, timeout=30,
    )
    if err is not None:
        if err.get("http_status") == 404:
            return {"success": True, "found": False, "uuid": uuid,
                    "message": "scan still processing — retry shortly"}
        return {**err, "uuid": uuid}
    page = data.get("page") or {}
    task = data.get("task") or {}
    verdicts = (data.get("verdicts") or {}).get("overall") or {}
    result = {
        "success": True,
        "found": True,
        "uuid": uuid,
        "submitted_url": task.get("url"),
        "final_url": page.get("url"),
        "domain": page.get("domain"),
        "ip": page.get("ip"),
        "country": page.get("country"),
        "malicious": verdicts.get("malicious"),
        "score": verdicts.get("score"),
        "screenshot": task.get("screenshotURL"),
    }
    sidecar = _persist("urlscan_result", uuid, result)
    if sidecar:
        result["sidecar_path"] = sidecar
    return result


@mcp.tool()
def misp_lookup(value: str) -> dict:
    """
    Search a MISP instance for attributes matching an IOC value.
    Requires MISP_URL and MISP_API_KEY. TLS verification can be disabled with
    MISP_VERIFY_TLS=0 for self-signed internal instances.
    """
    misp_url, misp_key = _env("MISP_URL"), _env("MISP_API_KEY")
    if not (misp_url and misp_key):
        return {"success": False,
                "error": "MISP not configured — set MISP_URL and MISP_API_KEY."}
    verify = os.environ.get("MISP_VERIFY_TLS", "1") != "0"
    data, err = _request_json(
        "MISP", "POST", f"{misp_url.rstrip('/')}/attributes/restSearch",
        json={"value": value, "limit": 50},
        headers={"Authorization": misp_key, "Accept": "application/json"},
        timeout=30, verify=verify,
    )
    if err is not None:
        return {**err, "value": value}
    try:
        attrs = (data.get("response") or {}).get("Attribute") or []
        # Galaxy clusters are MISP's structured threat-actor / malware labels.
        # They ride on the attribute (and its parent event) as `Galaxy` →
        # `GalaxyCluster`, and flattened `Tag` names like
        # 'misp-galaxy:threat-actor="APT29"'. Both feed attribution.
        tags: set[str] = set()
        galaxy_clusters: list[dict] = []
        seen_clusters: set[tuple] = set()
        for a in attrs:
            for t in (a.get("Tag") or []):
                name = t.get("name")
                if name:
                    tags.add(name)
            for g in (a.get("Galaxy") or []):
                gtype = g.get("type")
                for c in (g.get("GalaxyCluster") or []):
                    cval = c.get("value")
                    if not cval:
                        continue
                    key = (gtype, cval)
                    if key in seen_clusters:
                        continue
                    seen_clusters.add(key)
                    galaxy_clusters.append({
                        "galaxy_type": gtype,
                        "value": cval,
                        "tag_name": c.get("tag_name"),
                    })
        result = {
            "success": True,
            "value": value,
            "match_count": len(attrs),
            "tags": sorted(tags)[:40],
            "galaxy_clusters": galaxy_clusters[:40],
            "attributes": [{
                "type": a.get("type"),
                "category": a.get("category"),
                "value": a.get("value"),
                "event_id": a.get("event_id"),
                "to_ids": a.get("to_ids"),
                "comment": a.get("comment"),
            } for a in attrs[:50]],
        }
        sidecar = _persist("misp", value, result)
        if sidecar:
            result["sidecar_path"] = sidecar
        return result
    except Exception as e:
        return {"success": False, "error": str(e), "value": value}


def _whois_binary() -> Optional[str]:
    """Resolve the whois binary (system or user-local ~/.local/bin)."""
    import shutil
    found = shutil.which("whois")
    if found:
        return found
    local = os.path.expanduser("~/.local/bin/whois")
    return local if os.path.isfile(local) and os.access(local, os.X_OK) else None


@mcp.tool()
def whois_lookup(domain: str) -> dict:
    """
    WHOIS registration lookup for a domain (or IP) using the system `whois`
    binary. Returns registrar, creation/expiry dates, and name servers when
    parseable. No API key required. Also works with a user-local install at
    ~/.local/bin/whois.
    """
    from core import run
    binary = _whois_binary()
    if not binary:
        return {"success": False,
                "error": "whois not installed — apt install whois "
                         "(or place whois in ~/.local/bin)"}
    result = run([binary, domain], timeout=30)
    if result.get("success"):
        import re
        text = result.get("stdout", "")

        def _grab(pattern):
            m = re.search(pattern, text, re.IGNORECASE)
            return m.group(1).strip() if m else None

        result["parsed"] = {
            "registrar": _grab(r"Registrar:\s*(.+)"),
            "created": _grab(r"Creation Date:\s*(.+)"),
            "expires": _grab(r"(?:Registry Expiry Date|Expiration Date):\s*(.+)"),
            "name_servers": re.findall(r"Name Server:\s*(.+)", text,
                                       re.IGNORECASE)[:6],
            # RIPE / IP allocations often use these fields instead of "Registrar"
            "netname": _grab(r"netname:\s*(.+)"),
            "descr": _grab(r"descr:\s*(.+)"),
            "country": _grab(r"country:\s*(.+)"),
            "inetnum": _grab(r"inetnum:\s*(.+)"),
            "abuse_contact": _grab(r"[Aa]buse contact.*?'([^']+)'"),
        }
    return result


@mcp.tool()
def passive_dns(domain: str) -> dict:
    """
    Passive DNS resolutions for a domain via AlienVault OTX (requires
    OTX_API_KEY). Returns historically observed IPs and first/last-seen dates.
    """
    key = _env("OTX_API_KEY")
    if not key:
        return _no_key("OTX")
    data, err = _request_json(
        "OTX", "GET",
        f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
        headers={"X-OTX-API-KEY": key}, timeout=30,
    )
    if err is not None:
        if err.get("http_status") == 404:
            return {"success": True, "found": False, "domain": domain,
                    "record_count": 0, "records": []}
        return {**err, "domain": domain}
    records = [{
        "address": r.get("address"),
        "first": r.get("first"),
        "last": r.get("last"),
        "record_type": r.get("record_type"),
    } for r in (data.get("passive_dns") or [])[:100]]
    result = {"success": True, "found": True, "domain": domain,
              "record_count": len(records), "records": records}
    sidecar = _persist("passive_dns", domain, result)
    if sidecar:
        result["sidecar_path"] = sidecar
    return result


@mcp.tool()
def oui_lookup(mac_or_oui: str) -> dict:
    """Look up a MAC address / OUI prefix in the local IEEE OUI registry.

    Uses ``/usr/share/ieee-data/oui.txt`` (or ``/var/lib/ieee-data/oui.txt``).
    No API key and no internet required. Returns the registered organization
    for the 24-bit MA-L prefix.

    ALWAYS use this before claiming a MAC vendor/manufacturer. Never assert
    OUI→vendor from model memory — training data is often wrong.

    mac_or_oui: full MAC (``00:00:5e:00:53:01``) or prefix (``00:00:5E`` /
        ``00005E``). Separators ``:``, ``-``, ``.`` and spaces are accepted.
    """
    raw = (mac_or_oui or "").strip()
    hex_only = re.sub(r"[^0-9A-Fa-f]", "", raw).upper()
    if len(hex_only) < 6:
        return {
            "success": False,
            "error": "need at least 6 hex digits (24-bit OUI)",
            "input": mac_or_oui,
        }
    prefix = hex_only[:6]
    dashed = f"{prefix[0:2]}-{prefix[2:4]}-{prefix[4:6]}"
    paths = (
        "/usr/share/ieee-data/oui.txt",
        "/var/lib/ieee-data/oui.txt",
        os.path.expanduser("~/.local/share/ieee-data/oui.txt"),
    )
    oui_path = next((p for p in paths if os.path.isfile(p)), None)
    if not oui_path:
        return {
            "success": False,
            "error": "IEEE oui.txt not found on this host "
                     f"(tried: {', '.join(paths)})",
            "prefix": prefix,
            "input": mac_or_oui,
        }
    # Lines look like:  "B8-27-EB   (hex)\t\tRaspberry Pi Foundation"
    # or               "B827EB     (base 16)\t\tRaspberry Pi Foundation"
    pat_hex = re.compile(
        rf"^{re.escape(dashed)}\s+\(hex\)\s+(\S.*\S)\s*$", re.I)
    pat_base = re.compile(
        rf"^{re.escape(prefix)}\s+\(base\s+16\)\s+(\S.*\S)\s*$", re.I)
    organization = None
    try:
        with open(oui_path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = pat_hex.match(line.rstrip()) or pat_base.match(line.rstrip())
                if m:
                    organization = m.group(1).strip()
                    break
    except OSError as e:
        return {"success": False, "error": str(e), "prefix": prefix}

    result = {
        "success": True,
        "input": mac_or_oui,
        "prefix": prefix,
        "prefix_dashed": dashed,
        "found": organization is not None,
        "organization": organization,
        "source": oui_path,
        "registry": "IEEE MA-L (local oui.txt)",
    }
    if organization is None:
        result["message"] = (
            f"OUI {dashed} not present in local IEEE registry — do NOT invent "
            f"a vendor from model memory; record as unknown or HUNCH."
        )
    _persist("oui", prefix, result)
    return result


@mcp.tool()
def enrichment_status() -> dict:
    """Check which enrichment services are currently configured (API keys present)."""
    oui_paths = (
        "/usr/share/ieee-data/oui.txt",
        "/var/lib/ieee-data/oui.txt",
    )
    oui_ok = any(os.path.isfile(p) for p in oui_paths)
    return {
        # Empty-string .env entries must count as unset (bool("") is False).
        # Read live, like every lookup does — a key added through the
        # dashboard takes effect without restarting the process, and this
        # never reports a service as configured that a lookup would then
        # reject.
        "virustotal": bool(_env("VIRUSTOTAL_API_KEY")),
        "abuseipdb": bool(_env("ABUSEIPDB_API_KEY")),
        "otx": bool(_env("OTX_API_KEY")),
        "urlscan": bool(_env("URLSCAN_API_KEY")),
        "misp": bool(_env("MISP_URL") and _env("MISP_API_KEY")),
        "machinae": shutil.which("machinae") is not None,
        "whois": _whois_binary() is not None,
        "oui_lookup": oui_ok,
        "note": ("Set VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, OTX_API_KEY, "
                 "URLSCAN_API_KEY, and MISP_URL/MISP_API_KEY to enable full "
                 "enrichment. whois uses the system or ~/.local/bin binary. "
                 "oui_lookup uses the local IEEE oui.txt (no API key)."),
    }
