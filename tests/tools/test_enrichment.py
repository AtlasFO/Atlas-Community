"""Tests for tools/enrichment.py — API key graceful degradation and mocked HTTP."""
import pytest
import httpx
from unittest.mock import patch, MagicMock


def _resp(status, data):
    m = MagicMock()
    m.status_code = status
    m.json.return_value = data
    return m


# httpx is imported inside each tool function, so patch at the httpx module level
HTTP_PATCH = "httpx.request"


class TestVtLookupHash:
    def test_no_key_degrades_gracefully(self, monkeypatch):
        monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
        from tools.enrichment import vt_lookup_hash
        r = vt_lookup_hash("abc123")
        assert r["success"] is False
        assert "API key" in r["error"]

    def test_hash_found(self, monkeypatch):
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "testkey")
        attrs = {
            "last_analysis_stats": {"malicious": 10, "undetected": 60},
            "meaningful_name": "malware.exe",
        }
        with patch(HTTP_PATCH, return_value=_resp(200, {"data": {"attributes": attrs}})):
            from tools.enrichment import vt_lookup_hash
            r = vt_lookup_hash("deadbeef" * 8)
        assert r["success"] is True
        assert r["found"] is True
        assert r["malicious"] == 10

    def test_hash_not_found_404(self, monkeypatch):
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "testkey")
        with patch(HTTP_PATCH, return_value=_resp(404, {})):
            from tools.enrichment import vt_lookup_hash
            r = vt_lookup_hash("clean_hash")
        assert r["success"] is True
        assert r["found"] is False


class TestOtxLookup:
    def test_no_key_degrades(self, monkeypatch):
        monkeypatch.delenv("OTX_API_KEY", raising=False)
        from tools.enrichment import otx_lookup
        r = otx_lookup("1.2.3.4", "IPv4")
        assert r["success"] is False
        assert "API key" in r["error"]

    def test_unknown_type(self, monkeypatch):
        monkeypatch.setenv("OTX_API_KEY", "k")
        from tools.enrichment import otx_lookup
        r = otx_lookup("x", "bogus")
        assert r["success"] is False

    def test_pulse_summary(self, monkeypatch):
        monkeypatch.setenv("OTX_API_KEY", "k")
        body = {"pulse_info": {"count": 2, "pulses": [
            {"tags": ["apt"], "malware_families": ["Emotet"]},
            {"tags": ["c2"], "malware_families": []},
        ]}}
        with patch(HTTP_PATCH, return_value=_resp(200, body)):
            from tools.enrichment import otx_lookup
            r = otx_lookup("evil.example", "domain")
        assert r["success"] is True
        assert r["pulse_count"] == 2
        assert "Emotet" in r["malware_families"]


class TestUrlscanSearch:
    def test_no_key(self, monkeypatch):
        monkeypatch.delenv("URLSCAN_API_KEY", raising=False)
        from tools.enrichment import urlscan_search
        assert urlscan_search("domain:x")["success"] is False


class TestMispLookup:
    def test_not_configured(self, monkeypatch):
        monkeypatch.delenv("MISP_URL", raising=False)
        monkeypatch.delenv("MISP_API_KEY", raising=False)
        from tools.enrichment import misp_lookup
        assert misp_lookup("1.2.3.4")["success"] is False


class TestEnrichmentStatus:
    def test_reports_new_services(self):
        from tools.enrichment import enrichment_status
        s = enrichment_status()
        for key in ("otx", "urlscan", "misp", "whois"):
            assert key in s


class TestVtLookupIp:
    def test_no_key_degrades(self, monkeypatch):
        monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
        from tools.enrichment import vt_lookup_ip
        r = vt_lookup_ip("1.2.3.4")
        assert r["success"] is False

    def test_ip_lookup(self, monkeypatch):
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "testkey")
        attrs = {"last_analysis_stats": {"malicious": 5, "undetected": 70}}
        with patch(HTTP_PATCH, return_value=_resp(200, {"data": {"attributes": attrs}})):
            from tools.enrichment import vt_lookup_ip
            r = vt_lookup_ip("1.2.3.4")
        assert r["success"] is True
        assert r["ip"] == "1.2.3.4"


class TestVtLookupDomain:
    def test_no_key_degrades(self, monkeypatch):
        monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
        from tools.enrichment import vt_lookup_domain
        r = vt_lookup_domain("evil.com")
        assert r["success"] is False

    def test_domain_lookup(self, monkeypatch):
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "testkey")
        attrs = {"last_analysis_stats": {"malicious": 3, "undetected": 80}}
        with patch(HTTP_PATCH, return_value=_resp(200, {"data": {"attributes": attrs}})):
            from tools.enrichment import vt_lookup_domain
            r = vt_lookup_domain("evil.com")
        assert r["success"] is True
        assert r["domain"] == "evil.com"


class TestVtLookupUrl:
    def test_no_key_degrades(self, monkeypatch):
        monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
        from tools.enrichment import vt_lookup_url
        r = vt_lookup_url("https://bit.ly/evil")
        assert r["success"] is False

    def test_not_found_is_a_real_answer(self, monkeypatch):
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "testkey")
        with patch(HTTP_PATCH, return_value=_resp(404, {})):
            from tools.enrichment import vt_lookup_url
            r = vt_lookup_url("https://bit.ly/never-scanned")
        assert r["success"] is True
        assert r["found"] is False
        assert "urlscan_submit_scan" in r["message"]

    def test_found_returns_final_url_after_redirects(self, monkeypatch):
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "testkey")
        attrs = {
            "last_analysis_stats": {"malicious": 5, "undetected": 70},
            "last_final_url": "https://evil.example/landing",
        }
        with patch(HTTP_PATCH, return_value=_resp(200, {"data": {"attributes": attrs}})):
            from tools.enrichment import vt_lookup_url
            r = vt_lookup_url("https://bit.ly/evil")
        assert r["success"] is True
        assert r["found"] is True
        assert r["final_url"] == "https://evil.example/landing"
        assert r["malicious"] == 5


class TestUrlscanSubmitScan:
    def test_no_key_degrades(self, monkeypatch):
        monkeypatch.delenv("URLSCAN_API_KEY", raising=False)
        from tools.enrichment import urlscan_submit_scan
        r = urlscan_submit_scan("https://bit.ly/evil")
        assert r["success"] is False

    def test_refuses_public_visibility(self, monkeypatch):
        monkeypatch.setenv("URLSCAN_API_KEY", "testkey")
        from tools.enrichment import urlscan_submit_scan
        r = urlscan_submit_scan("https://bit.ly/evil", visibility="public")
        assert r["success"] is False
        assert "public" in r["error"]

    def test_submits_unlisted_by_default(self, monkeypatch):
        monkeypatch.setenv("URLSCAN_API_KEY", "testkey")
        body = {"uuid": "abc-123", "result": "https://urlscan.io/result/abc-123/"}
        with patch(HTTP_PATCH, return_value=_resp(200, body)) as m:
            from tools.enrichment import urlscan_submit_scan
            r = urlscan_submit_scan("https://bit.ly/evil")
        assert r["success"] is True
        assert r["uuid"] == "abc-123"
        assert r["visibility"] == "unlisted"
        assert m.call_args.kwargs["json"]["visibility"] == "unlisted"


class TestUrlscanFetchResult:
    def test_no_key_degrades(self, monkeypatch):
        monkeypatch.delenv("URLSCAN_API_KEY", raising=False)
        from tools.enrichment import urlscan_fetch_result
        r = urlscan_fetch_result("abc-123")
        assert r["success"] is False

    def test_still_processing_is_not_a_failure(self, monkeypatch):
        monkeypatch.setenv("URLSCAN_API_KEY", "testkey")
        with patch(HTTP_PATCH, return_value=_resp(404, {})):
            from tools.enrichment import urlscan_fetch_result
            r = urlscan_fetch_result("abc-123")
        assert r["success"] is True
        assert r["found"] is False

    def test_completed_scan_returns_final_url(self, monkeypatch):
        monkeypatch.setenv("URLSCAN_API_KEY", "testkey")
        body = {
            "page": {"url": "https://evil.example/landing", "domain": "evil.example",
                     "ip": "1.2.3.4", "country": "RU"},
            "task": {"url": "https://bit.ly/evil", "screenshotURL": "https://urlscan.io/shot.png"},
            "verdicts": {"overall": {"malicious": True, "score": 90}},
        }
        with patch(HTTP_PATCH, return_value=_resp(200, body)):
            from tools.enrichment import urlscan_fetch_result
            r = urlscan_fetch_result("abc-123")
        assert r["success"] is True
        assert r["found"] is True
        assert r["final_url"] == "https://evil.example/landing"
        assert r["malicious"] is True


class TestAbuseIpdb:
    def test_no_key_degrades(self, monkeypatch):
        monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
        from tools.enrichment import abuseipdb_check
        r = abuseipdb_check("1.2.3.4")
        assert r["success"] is False
        assert "API key" in r["error"]

    def test_ip_check(self, monkeypatch):
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "testkey")
        data = {"data": {"abuseConfidenceScore": 85, "totalReports": 10, "countryCode": "CN"}}
        with patch(HTTP_PATCH, return_value=_resp(200, data)):
            from tools.enrichment import abuseipdb_check
            r = abuseipdb_check("1.2.3.4")
        assert r["success"] is True
        assert r["abuse_confidence_score"] == 85


class TestHttpErrorsAreNotCleanVerdicts:
    """Every provider answers an error with a parseable JSON body whose
    statistics block is simply absent. Read only as a payload, that is shaped
    exactly like "no engine flagged this indicator" — a false negative
    presented as a clean verdict. These pin the failure open."""

    @pytest.fixture(autouse=True)
    def _fast(self, monkeypatch):
        # One attempt: retry/backoff timing is covered separately.
        monkeypatch.setattr("tools.enrichment._MAX_ATTEMPTS", 1)

    @pytest.mark.parametrize("status", [401, 403])
    def test_rejected_key_is_a_failure_not_zero_detections(self, monkeypatch, status):
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "expired")
        body = {"error": {"code": "WrongCredentialsError", "message": "Wrong key"}}
        with patch(HTTP_PATCH, return_value=_resp(status, body)):
            from tools.enrichment import vt_lookup_hash
            r = vt_lookup_hash("deadbeef" * 8)
        assert r["success"] is False
        assert r["http_status"] == status
        assert "malicious" not in r          # never a verdict
        assert "key" in r["error"].lower()

    def test_rate_limit_is_a_failure_not_zero_detections(self, monkeypatch):
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "k")
        with patch(HTTP_PATCH, return_value=_resp(429, {"error": {}})):
            from tools.enrichment import vt_lookup_hash
            r = vt_lookup_hash("deadbeef" * 8)
        assert r["success"] is False
        assert r["http_status"] == 429
        assert "malicious" not in r

    def test_server_error_is_a_failure(self, monkeypatch):
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "k")
        with patch(HTTP_PATCH, return_value=_resp(503, {})):
            from tools.enrichment import vt_lookup_ip
            r = vt_lookup_ip("1.2.3.4")
        assert r["success"] is False
        assert r["http_status"] == 503

    def test_otx_rejected_key_is_not_an_empty_pulse_list(self, monkeypatch):
        monkeypatch.setenv("OTX_API_KEY", "expired")
        with patch(HTTP_PATCH, return_value=_resp(403, {"detail": "bad key"})):
            from tools.enrichment import otx_lookup
            r = otx_lookup("1.2.3.4", "IPv4")
        assert r["success"] is False
        assert "pulse_count" not in r        # 0 pulses would read as "no intel"

    def test_abuseipdb_rejected_key_is_not_a_null_score(self, monkeypatch):
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "expired")
        with patch(HTTP_PATCH, return_value=_resp(401, {"errors": [{"detail": "x"}]})):
            from tools.enrichment import abuseipdb_check
            r = abuseipdb_check("1.2.3.4")
        assert r["success"] is False
        assert "abuse_confidence_score" not in r

    def test_unreadable_body_is_a_failure(self, monkeypatch):
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "k")
        broken = MagicMock()
        broken.status_code = 200
        broken.json.side_effect = ValueError("not json")
        with patch(HTTP_PATCH, return_value=broken):
            from tools.enrichment import vt_lookup_hash
            r = vt_lookup_hash("deadbeef" * 8)
        assert r["success"] is False
        assert "unreadable" in r["error"]

    def test_404_is_still_a_real_answer(self, monkeypatch):
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "k")
        with patch(HTTP_PATCH, return_value=_resp(404, {})):
            from tools.enrichment import vt_lookup_hash
            r = vt_lookup_hash("unknown")
        assert r["success"] is True and r["found"] is False


class TestRateLimitRetry:
    def test_retries_then_succeeds(self, monkeypatch):
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "k")
        monkeypatch.setattr("tools.enrichment.time.sleep", lambda _s: None)
        ok = _resp(200, {"data": {"attributes": {
            "last_analysis_stats": {"malicious": 7, "undetected": 60}}}})
        throttled = _resp(429, {"error": {}})
        throttled.headers = {"Retry-After": "1"}
        with patch(HTTP_PATCH, side_effect=[throttled, throttled, ok]):
            from tools.enrichment import vt_lookup_hash
            r = vt_lookup_hash("deadbeef" * 8)
        assert r["success"] is True and r["malicious"] == 7

    def test_gives_up_with_a_clear_error(self, monkeypatch):
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "k")
        monkeypatch.setattr("tools.enrichment.time.sleep", lambda _s: None)
        throttled = _resp(429, {"error": {}})
        throttled.headers = {}
        with patch(HTTP_PATCH, return_value=throttled):
            from tools.enrichment import vt_lookup_hash
            r = vt_lookup_hash("deadbeef" * 8)
        assert r["success"] is False and r["http_status"] == 429
        assert "rate limit" in r["error"].lower()


class TestKeysReadAtCallTime:
    """A key added through the dashboard must take effect without a restart —
    it used to be captured into a module constant at import."""

    def test_key_set_after_import_is_picked_up(self, monkeypatch):
        monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
        from tools.enrichment import vt_lookup_hash, enrichment_status
        assert vt_lookup_hash("abc")["success"] is False
        assert enrichment_status()["virustotal"] is False
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "added-later")
        assert enrichment_status()["virustotal"] is True

    def test_empty_string_counts_as_unset(self, monkeypatch):
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "   ")
        from tools.enrichment import enrichment_status
        assert enrichment_status()["virustotal"] is False
