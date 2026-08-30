import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load_module(filename, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


v1 = load_module("xpl_toolkit.py", "xpl_toolkit_v1")
v2 = load_module("xpl_toolkit_v2.py", "xpl_toolkit_v2")


class SecurityTests(unittest.TestCase):
    def test_v2_validates_ips_domains_and_rejects_urls(self):
        self.assertEqual(v2.Security.validate_target("192.168.1.10"), (True, "192.168.1.10"))
        self.assertEqual(v2.Security.validate_target("example.com"), (True, "example.com"))
        self.assertEqual(v2.Security.validate_target("2001:db8::1"), (True, "2001:db8::1"))
        self.assertEqual(v2.Security.validate_target("https://example.com"), (False, None))
        self.assertEqual(v2.Security.validate_target("example.com; id"), (False, None))

    def test_v1_validates_target(self):
        self.assertEqual(v1.validate_target("10.0.0.1"), (True, "10.0.0.1"))
        self.assertEqual(v1.validate_target("bad target"), (False, None))

    def test_ports_accept_numeric_strings(self):
        self.assertTrue(v2.Security.validate_port("443"))
        self.assertFalse(v2.Security.validate_port("0"))
        self.assertFalse(v2.Security.validate_port("65536"))
        self.assertFalse(v2.Security.validate_port("ssh"))

    def test_metasploit_alias_uses_real_binary(self):
        self.assertEqual(v2.tool_command("metasploit"), "msfconsole")
        self.assertEqual(v1.TOOL_BINARIES["metasploit"], "msfconsole")


class CacheAndReportTests(unittest.TestCase):
    def test_empty_cached_result_is_a_cache_hit(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = v2.CVECache(str(Path(tmp) / "cache.db"))
            cache.put("no-result", [], 0)
            cached, total = cache.get("no-result")
            cache.close()
            self.assertEqual(cached, [])
            self.assertEqual(total, 0)

    def test_cve_parser_and_html_escape(self):
        raw = [{
            "cve": {
                "id": "CVE-2099-0001",
                "published": "2099-01-02T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "<script>alert(1)</script>"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1"}}]},
            }
        }]
        results = v2.parse_cve_results(raw)
        self.assertEqual(results[0]["cve_id"], "CVE-2099-0001")
        self.assertEqual(results[0]["severity"], "CRITICAL")

        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp) / "session"
            (session / "assets").mkdir(parents=True)
            html_path, _ = v2.generate_report(
                target="example.com",
                vuln="<img src=x onerror=alert(1)>",
                session_dir=str(session),
                status="INFO",
                cve_results=results,
                services=[{"port": "443", "service": "https", "version": "<b>"}],
                waf=["<script>"],
                tls_info={"supported": ["TLSv1_3"], "certificate": {}, "warnings": []},
                raw_output="safe",
                auth_mode="verify",
                tools_used="unit-test",
            )
            html = Path(html_path).read_text(encoding="utf-8")
            self.assertNotIn("<script>alert(1)</script>", html)
            self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
            self.assertIn("&lt;img src=x onerror=alert(1)&gt;", html)


class WordlistRegressionTests(unittest.TestCase):
    def test_v1_wordlist_does_not_require_a_session_to_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "words.txt"

            def fake_run(*args, **kwargs):
                output.write_text("alpha\nbeta\n", encoding="utf-8")
                return subprocess.CompletedProcess(args[0], 0, "", "")

            with patch.object(v1, "tool_installed", return_value=True), patch.object(v1.subprocess, "run", side_effect=fake_run):
                self.assertTrue(v1.generate_wordlist("https://example.com", str(output)))
            self.assertEqual(output.read_text(encoding="utf-8"), "alpha\nbeta\n")


if __name__ == "__main__":
    unittest.main()
