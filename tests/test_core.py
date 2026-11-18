import base64
import unittest

from ssh_known_hosts_kit import KnownHost, parse_known_host
from ssh_known_hosts_kit.core import KnownHostsError, parse_known_hosts


KEY = base64.b64encode(b"\x00\x01\x02\x03").decode("ascii")


class TestParseKnownHost(unittest.TestCase):
    def test_plain_record(self):
        got = parse_known_host(f"host1 ssh-ed25519 {KEY}")
        self.assertEqual(got.hosts, "host1")
        self.assertEqual(got.key_type, "ssh-ed25519")
        self.assertEqual(got.key, b"\x00\x01\x02\x03")
        self.assertIsNone(got.marker)
        self.assertFalse(got.hashed)

    def test_comma_separated_hosts(self):
        got = parse_known_host(f"host1,host2 ssh-rsa {KEY}")
        self.assertEqual(got.hosts, "host1,host2")

    def test_hashed_host_token(self):
        token = "|1|c2FsdA==|aGFzaA=="
        got = parse_known_host(f"{token} ssh-rsa {KEY}")
        self.assertTrue(got.hashed)
        self.assertEqual(got.hosts, token)

    def test_marker_cert_authority(self):
        got = parse_known_host(f"@cert-authority host1 ssh-rsa {KEY}")
        self.assertEqual(got.marker, "@cert-authority")
        self.assertEqual(got.hosts, "host1")

    def test_marker_revoked(self):
        got = parse_known_host(f"@revoked host1 ssh-rsa {KEY}")
        self.assertEqual(got.marker, "@revoked")

    def test_trailing_comment_is_ignored(self):
        got = parse_known_host(f"host1 ssh-rsa {KEY} some comment here")
        self.assertEqual(got.hosts, "host1")
        self.assertEqual(got.key_type, "ssh-rsa")

    def test_unpadded_base64_is_accepted(self):
        # b"\x00\x01\x02\x03" encodes to "AAECAw=="; strip the padding.
        got = parse_known_host("host1 ssh-rsa AAECAw")
        self.assertEqual(got.key, b"\x00\x01\x02\x03")

    def test_blank_line_returns_none(self):
        self.assertIsNone(parse_known_host(""))
        self.assertIsNone(parse_known_host("   \t  "))

    def test_comment_returns_none(self):
        self.assertIsNone(parse_known_host("# a comment"))
        self.assertIsNone(parse_known_host("   # indented"))

    def test_too_few_fields_raises(self):
        with self.assertRaises(KnownHostsError):
            parse_known_host("host1 ssh-rsa")

    def test_bad_base64_raises(self):
        with self.assertRaises(KnownHostsError):
            parse_known_host("host1 ssh-rsa not!base64")

    def test_marker_without_hosts_raises(self):
        with self.assertRaises(KnownHostsError):
            parse_known_host("@revoked")


class TestParseKnownHosts(unittest.TestCase):
    def test_skips_comments_and_blanks(self):
        text = f"# header\n\nhost1 ssh-rsa {KEY}\n\n# trailing\n"
        got = parse_known_hosts(text)
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].hosts, "host1")

    def test_returns_tuple(self):
        got = parse_known_hosts(f"host1 ssh-rsa {KEY}")
        self.assertIsInstance(got, tuple)

    def test_empty_text(self):
        self.assertEqual(parse_known_hosts(""), ())


if __name__ == "__main__":
    unittest.main()
