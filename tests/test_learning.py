"""Tests for Code Learning modules (L.1-L.4)."""

import json
from pathlib import Path

import pytest

from app import storage
from app.learning.fingerprint import extract_fingerprint, fingerprint_diff
from app.learning.baseline import compute_baseline, check_deviations, MIN_SAMPLES
from app.learning.reputation import record_scan, get_reputation, get_all_reputations


# --- L.1: Fingerprinting ---

class TestFingerprinting:
    def test_extract_python_fingerprint(self, fixture_integration):
        fp = extract_fingerprint(fixture_integration, domain="test_domain", repo_url="https://github.com/test")
        assert fp["domain"] == "test_domain"
        assert fp["py_files"] >= 2
        assert fp["total_lines"] > 0
        assert "subprocess" in fp["imports"]
        assert isinstance(fp["fingerprint_hash"], str)
        assert len(fp["fingerprint_hash"]) == 16

    def test_extract_js_fingerprint(self, fixture_card):
        fp = extract_fingerprint(fixture_card, domain="test_card")
        assert fp["js_files"] >= 1
        assert ".js" in fp["file_types"]

    def test_extract_dangerous_python(self, fixture_dangerous_py):
        fp = extract_fingerprint(fixture_dangerous_py, domain="evil")
        assert "subprocess" in fp["imports"]
        assert "pickle" in fp["imports"]
        assert "ctypes" in fp["imports"]

    def test_extract_network_domains(self, fixture_dangerous_js):
        fp = extract_fingerprint(fixture_dangerous_js)
        assert "evil.com" in fp["network_domains"]

    def test_fingerprint_diff_detects_changes(self):
        old = {"imports": ["os", "logging"], "ha_apis": [], "network_domains": [], "total_lines": 100}
        new = {"imports": ["os", "subprocess"], "ha_apis": ["hass.services"], "network_domains": ["evil.com"], "total_lines": 100}
        diff = fingerprint_diff(old, new)
        assert "imports" in diff
        assert "subprocess" in diff["imports"]["added"]
        assert "logging" in diff["imports"]["removed"]
        assert "ha_apis" in diff
        assert "network_domains" in diff

    def test_fingerprint_diff_size_change(self):
        old = {"imports": [], "ha_apis": [], "network_domains": [], "total_lines": 100}
        new = {"imports": [], "ha_apis": [], "network_domains": [], "total_lines": 200}
        diff = fingerprint_diff(old, new)
        assert "size" in diff
        assert diff["size"]["change_pct"] == 100.0

    def test_fingerprint_no_diff(self):
        fp = {"imports": ["os"], "ha_apis": [], "network_domains": [], "total_lines": 100}
        diff = fingerprint_diff(fp, fp)
        assert diff == {}

    def test_save_and_load_fingerprint(self, fixture_integration):
        fp = extract_fingerprint(fixture_integration, domain="test_domain", repo_url="https://github.com/test")
        storage.save_fingerprint("scan-001", fp)
        loaded = storage.get_last_fingerprint(domain="test_domain")
        assert loaded is not None
        assert loaded["domain"] == "test_domain"
        assert loaded["imports"] == fp["imports"]
        assert loaded["fingerprint_hash"] == fp["fingerprint_hash"]

    def test_load_nonexistent_fingerprint(self):
        loaded = storage.get_last_fingerprint(domain="nonexistent")
        assert loaded is None


# --- L.2: Baseline ---

class TestBaseline:
    def _populate_history(self, conn, n=20):
        """Insert N scan history rows with varied data."""
        for i in range(n):
            conn.execute(
                "INSERT INTO scan_history "
                "(domain, repo_url, version, score, findings_count, total_lines, "
                " py_files, js_files, network_domain_count, scanned_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
                (f"domain_{i}", f"https://github.com/test/{i}", "1.0",
                 5.0 + (i % 5), 3 + (i % 10), 100 + i * 10,
                 2 + (i % 3), i % 2, i % 4),
            )
        conn.commit()

    def test_baseline_not_enough_data(self):
        conn = storage.get_conn()
        result = compute_baseline(conn)
        assert result is None  # No scan history

    def test_baseline_computed(self):
        conn = storage.get_conn()
        self._populate_history(conn, n=MIN_SAMPLES)
        result = compute_baseline(conn)
        assert result is not None
        assert "findings_count" in result
        assert "score" in result
        assert result["findings_count"]["sample_count"] == MIN_SAMPLES

    def test_check_deviations_no_baseline(self):
        conn = storage.get_conn()
        alerts = check_deviations(conn, {"total_lines": 100, "network_domains": []}, 5.0, 5)
        assert alerts == []

    def test_check_deviations_extreme_value(self):
        conn = storage.get_conn()
        self._populate_history(conn, n=20)
        compute_baseline(conn)
        # 999 findings should deviate from mean ~7.5
        alerts = check_deviations(conn, {"total_lines": 100, "network_domains": []}, 5.0, 999)
        finding_alerts = [a for a in alerts if a["metric"] == "findings_count"]
        assert len(finding_alerts) == 1
        assert finding_alerts[0]["direction"] == "above"


# --- L.3: Whitelist ---

class TestWhitelist:
    def test_add_and_list(self):
        ph = storage.add_whitelist("network", "sensor.py", "Connects to evil.com", "Known safe")
        wl = storage.get_whitelist()
        assert len(wl) == 1
        assert wl[0]["pattern_hash"] == ph
        assert wl[0]["category"] == "network"
        assert wl[0]["reason"] == "Known safe"

    def test_is_whitelisted_exact(self):
        storage.add_whitelist("network", "sensor.py", "Connects to evil.com")
        assert storage.is_whitelisted("network", "sensor.py", "Connects to evil.com")

    def test_is_whitelisted_file_pattern_match(self):
        storage.add_whitelist("network", "sensor.py", "Some other description")
        # Category matches and file_pattern "sensor.py" is a substring of the path
        assert storage.is_whitelisted("network", "custom_components/test/sensor.py", "totally different desc")

    def test_not_whitelisted(self):
        storage.add_whitelist("network", "sensor.py", "Connects to evil.com")
        assert not storage.is_whitelisted("code_injection", "other.py", "different issue")

    def test_remove_whitelist(self):
        ph = storage.add_whitelist("network", "sensor.py", "Connects to evil.com")
        assert storage.remove_whitelist(ph)
        assert storage.get_whitelist() == []
        assert not storage.is_whitelisted("network", "sensor.py", "Connects to evil.com")

    def test_remove_nonexistent(self):
        assert not storage.remove_whitelist("doesnotexist")


# --- L.4: Reputation ---

class TestReputation:
    def test_record_and_get(self):
        conn = storage.get_conn()
        record_scan(conn, "test_domain", "https://github.com/test", "1.0", 8.0, 3)
        record_scan(conn, "test_domain", "https://github.com/test", "1.1", 8.5, 2)
        rep = get_reputation(conn, domain="test_domain")
        assert rep is not None
        assert rep["scans_count"] == 2
        assert rep["avg_score"] == 8.2  # (8.0 + 8.5) / 2 = 8.25, rounded to 8.2
        assert rep["last_score"] == 8.5
        assert rep["trend"] == "stable"  # diff 0.5, borderline

    def test_improving_trend(self):
        conn = storage.get_conn()
        record_scan(conn, "imp", "url", "1.0", 4.0, 10)
        record_scan(conn, "imp", "url", "1.1", 6.0, 5)
        record_scan(conn, "imp", "url", "1.2", 8.0, 2)
        rep = get_reputation(conn, domain="imp")
        assert rep["trend"] == "improving"
        assert rep["trend_symbol"] == "\u2191"

    def test_declining_trend(self):
        conn = storage.get_conn()
        record_scan(conn, "dec", "url", "1.0", 9.0, 1)
        record_scan(conn, "dec", "url", "1.1", 7.0, 5)
        record_scan(conn, "dec", "url", "1.2", 5.0, 12)
        rep = get_reputation(conn, domain="dec")
        assert rep["trend"] == "declining"
        assert rep["trend_symbol"] == "\u2193"

    def test_no_reputation(self):
        conn = storage.get_conn()
        rep = get_reputation(conn, domain="nonexistent")
        assert rep is None

    def test_get_all_reputations(self):
        conn = storage.get_conn()
        record_scan(conn, "a", "url_a", "1.0", 8.0, 3)
        record_scan(conn, "b", "url_b", "1.0", 6.0, 7)
        all_rep = get_all_reputations(conn)
        assert len(all_rep) == 2
        domains = {r["domain"] for r in all_rep}
        assert domains == {"a", "b"}

    def test_reputation_by_url(self):
        conn = storage.get_conn()
        record_scan(conn, "", "https://github.com/test/repo", "1.0", 7.0, 5)
        rep = get_reputation(conn, repo_url="https://github.com/test/repo")
        assert rep is not None
        assert rep["scans_count"] == 1
