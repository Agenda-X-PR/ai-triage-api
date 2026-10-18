"""Tests for the analysis rules."""

import unittest

from sec_triage import Event, analyze


def make_event(line, ip, path=None, status=None):
    return Event(line=line, source=ip, ip=ip, path=path, status=status)


class TestRepeatedAuthDenials(unittest.TestCase):

    def test_fires_on_5_401s(self):
        events = [make_event(i, "1.2.3.4", "/login", 401) for i in range(1, 6)]
        findings = analyze(events, threshold=5)
        rules = [f.rule for f in findings]
        self.assertIn("repeated_auth_or_access_denials", rules)

    def test_does_not_fire_below_threshold(self):
        events = [make_event(i, "1.2.3.4", "/login", 401) for i in range(1, 5)]
        findings = analyze(events, threshold=5)
        rules = [f.rule for f in findings]
        self.assertNotIn("repeated_auth_or_access_denials", rules)

    def test_severity_is_high(self):
        events = [make_event(i, "1.2.3.4", "/login", 401) for i in range(1, 6)]
        findings = analyze(events, threshold=5)
        auth = [f for f in findings if f.rule == "repeated_auth_or_access_denials"][0]
        self.assertEqual(auth.severity, "high")


class TestSensitivePathProbe(unittest.TestCase):

    def test_aggregates_same_path_into_one_finding(self):
        events = [make_event(i, "9.9.9.9", "/.env", 404) for i in range(1, 4)]
        findings = analyze(events, threshold=5)
        probes = [f for f in findings if f.rule == "sensitive_path_probe"]
        self.assertEqual(len(probes), 1, "should be ONE finding, not one per request")
        self.assertEqual(probes[0].count, 3)

    def test_different_paths_produce_separate_findings(self):
        events = [
            make_event(1, "9.9.9.9", "/.env", 404),
            make_event(2, "9.9.9.9", "/wp-admin", 404),
        ]
        findings = analyze(events, threshold=5)
        probes = [f for f in findings if f.rule == "sensitive_path_probe"]
        self.assertEqual(len(probes), 2)

    def test_different_ips_produce_separate_findings(self):
        events = [
            make_event(1, "9.9.9.9", "/.env", 404),
            make_event(2, "8.8.8.8", "/.env", 404),
        ]
        findings = analyze(events, threshold=5)
        probes = [f for f in findings if f.rule == "sensitive_path_probe"]
        self.assertEqual(len(probes), 2)


class Test404Burst(unittest.TestCase):

    def test_fires_on_burst_within_window(self):
        events = [make_event(i, "1.1.1.1", f"/p{i}", 404) for i in range(1, 6)]
        findings = analyze(events, threshold=5, window_lines=100)
        rules = [f.rule for f in findings]
        self.assertIn("http_404_burst", rules)

    def test_does_not_fire_when_spread_beyond_window(self):
        # 5 x 404s but each 200 lines apart — should NOT count as a burst
        events = [make_event(i * 200, "1.1.1.1", f"/p{i}", 404) for i in range(1, 6)]
        findings = analyze(events, threshold=5, window_lines=100)
        rules = [f.rule for f in findings]
        self.assertNotIn("http_404_burst", rules)

    def test_fires_once_per_ip(self):
        events = [make_event(i, "1.1.1.1", f"/p{i}", 404) for i in range(1, 6)]
        findings = analyze(events, threshold=5)
        bursts = [f for f in findings if f.rule == "http_404_burst"]
        self.assertEqual(len(bursts), 1)


class TestSshGuessing(unittest.TestCase):

    def test_fires_on_5_ssh_failures(self):
        events = [
            Event(line=i, source="7.7.7.7", ip="7.7.7.7", path="ssh-auth-failure")
            for i in range(1, 6)
        ]
        findings = analyze(events, threshold=5)
        rules = [f.rule for f in findings]
        self.assertIn("ssh_password_guessing", rules)


class TestCleanLog(unittest.TestCase):

    def test_normal_traffic_produces_no_findings(self):
        events = [
            make_event(1, "1.1.1.1", "/", 200),
            make_event(2, "1.1.1.1", "/about", 200),
            make_event(3, "1.1.1.1", "/contact", 200),
        ]
        findings = analyze(events, threshold=5)
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()