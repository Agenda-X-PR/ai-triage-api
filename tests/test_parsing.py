"""Tests for log line parsing."""

import unittest

from sec_triage import parse_line


class TestApacheParsing(unittest.TestCase):

    def test_parses_apache_combined_line(self):
        line = '203.0.113.8 - - [18/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 512'
        event = parse_line(line, 1)
        self.assertEqual(event.ip, "203.0.113.8")
        self.assertEqual(event.method, "GET")
        self.assertEqual(event.path, "/")
        self.assertEqual(event.status, 200)

    def test_parses_apache_401(self):
        line = '192.0.2.77 - - [18/Oct/2026:10:00:02 +0000] "POST /login HTTP/1.1" 401 80'
        event = parse_line(line, 1)
        self.assertEqual(event.ip, "192.0.2.77")
        self.assertEqual(event.method, "POST")
        self.assertEqual(event.path, "/login")
        self.assertEqual(event.status, 401)

    def test_parses_apache_404(self):
        line = '198.51.100.44 - - [18/Oct/2026:10:00:01 +0000] "GET /.env HTTP/1.1" 404 120'
        event = parse_line(line, 1)
        self.assertEqual(event.path, "/.env")
        self.assertEqual(event.status, 404)


class TestJsonParsing(unittest.TestCase):

    def test_parses_json_line(self):
        line = '{"ip":"10.0.0.1","method":"GET","path":"/api","status":200}'
        event = parse_line(line, 1)
        self.assertEqual(event.ip, "10.0.0.1")
        self.assertEqual(event.method, "GET")
        self.assertEqual(event.path, "/api")
        self.assertEqual(event.status, 200)

    def test_parses_json_with_client_ip_key(self):
        line = '{"client_ip":"10.0.0.2","status_code":403,"url":"/admin"}'
        event = parse_line(line, 1)
        self.assertEqual(event.ip, "10.0.0.2")
        self.assertEqual(event.path, "/admin")
        self.assertEqual(event.status, 403)


class TestSshParsing(unittest.TestCase):

    def test_parses_ssh_failed_password(self):
        line = "Oct 18 10:00:00 host sshd[1234]: Failed password for root from 203.0.113.99 port 22 ssh2"
        event = parse_line(line, 1)
        self.assertEqual(event.ip, "203.0.113.99")
        self.assertEqual(event.path, "ssh-auth-failure")

    def test_parses_ssh_invalid_user(self):
        line = "Oct 18 10:00:00 host sshd[1234]: Failed password for invalid user admin from 203.0.113.99 port 22 ssh2"
        event = parse_line(line, 1)
        self.assertEqual(event.ip, "203.0.113.99")
        self.assertEqual(event.path, "ssh-auth-failure")


class TestUnknownLines(unittest.TestCase):

    def test_unparseable_line_does_not_crash(self):
        event = parse_line("completely unstructured garbage", 1)
        self.assertEqual(event.line, 1)
        self.assertEqual(event.ip, "unknown")
        self.assertIsNone(event.status)


if __name__ == "__main__":
    unittest.main()