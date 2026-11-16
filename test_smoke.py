"""Self-test: python -m unittest discover -s tests -v   (or double-click 5_Run_Self_Test.bat)"""
import io
import json
import os
import socket
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from secops_agent.cli import main as cli_main            # noqa: E402
from secops_agent.engine import Agent                     # noqa: E402
from secops_agent.report import render_html, render_json, render_text  # noqa: E402

SAMPLES = ROOT / "data" / "sample_alerts"
EXPECTED = {
    "01_phishing_powershell_c2.json": "Critical",
    "02_credential_dumping_lateral_movement.json": "Critical",
    "03_ransomware_precursors_and_exfil.json": "Critical",
    "04_password_spray_impossible_travel.json": "High",
    "05_benign_eicar_test_file.json": "Low",
    "06_raw_log_rdp_intrusion.log": "Critical",
}
DISRUPTIVE = ("Network Containment", "Identity Revocation", "Perimeter Block")


class AgentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.agent = Agent()

    def test_severity_of_every_sample(self):
        for name, expected in EXPECTED.items():
            inc = self.agent.investigate_file(SAMPLES / name)
            self.assertEqual(inc.severity, expected, name)
            self.assertTrue(0 <= inc.confidence <= 100)

    def test_report_follows_required_format(self):
        for name in EXPECTED:
            text = render_text(self.agent.investigate_file(SAMPLES / name))
            self.assertTrue(text.startswith("[SEC-OPS INCIDENT REPORT] - "))
            for heading in ("Severity Assessment:", "Confidence Score:", "1. Executive Summary & Root Cause",
                            "2. Threat Intelligence & Entity Enrichment", "3. Reconstructed Incident Timeline",
                            "4. Autonomous SOAR Isolation Playbook"):
                self.assertIn(heading, text, name)

    def test_benign_alert_triggers_no_containment(self):
        inc = self.agent.investigate_file(SAMPLES / "05_benign_eicar_test_file.json")
        self.assertFalse([s for s in inc.playbook if s.category in DISRUPTIVE])

    def test_guardrails_hold_protected_assets_for_approval(self):
        inc = self.agent.investigate_file(SAMPLES / "02_credential_dumping_lateral_movement.json")
        held = [s for s in inc.playbook if s.status == "HELD_FOR_APPROVAL"]
        self.assertTrue(held)
        self.assertTrue(all(s.guard for s in held))

    def test_critical_alert_builds_containment_playbook(self):
        inc = self.agent.investigate_file(SAMPLES / "01_phishing_powershell_c2.json")
        cats = {s.category for s in inc.playbook}
        self.assertIn("Network Containment", cats)
        self.assertIn("Identity Revocation", cats)
        self.assertIn("Perimeter Block", cats)

    def test_json_and_html_render(self):
        inc = self.agent.investigate_file(SAMPLES / "03_ransomware_precursors_and_exfil.json")
        self.assertEqual(json.loads(render_json(inc))["severity"], inc.severity)
        self.assertIn("<html", render_html(inc))

    def test_no_network_access_during_investigation(self):
        real = socket.socket

        def blocked(*a, **k):
            raise AssertionError("The agent tried to open a network socket")
        socket.socket = blocked
        try:
            for name in EXPECTED:
                self.agent.investigate_file(SAMPLES / name)
        finally:
            socket.socket = real


class CliTests(unittest.TestCase):
    def test_cli_in_a_path_with_spaces_and_parentheses(self):
        with tempfile.TemporaryDirectory(prefix="Agentic AI (SecOps) ") as tmp:
            out = Path(tmp) / "my reports"
            alert = Path(tmp) / "alert with space.json"
            alert.write_text(json.dumps({
                "alert_id": "TEST-\u00e9-1", "name": "Unicode name \u20ac test",
                "events": [{"timestamp": "2026-10-27T10:00:00Z", "host": "PC-1", "user": "bob",
                            "process": "C:\\Windows\\System32\\cmd.exe", "command_line": "whoami"}]}),
                encoding="utf-8")
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = cli_main([str(alert), "--out", str(out)])
            self.assertEqual(code, 0, buf.getvalue())
            self.assertTrue((out / "index.html").exists())
            self.assertTrue(any(p.suffix == ".txt" for p in out.iterdir()))

    def test_cli_missing_file_returns_error_code(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli_main([os.path.join(tempfile.gettempdir(), "definitely-missing-alert.json")])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
