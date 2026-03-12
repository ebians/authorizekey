"""Unit tests for key_handler module."""
import base64
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

# Allow imports from repo root regardless of how pytest is invoked
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from key_handler import add_authorized_key, validate_ssh_public_key  # noqa: E402


class TestValidateSshPublicKey(unittest.TestCase):
    """Tests for validate_ssh_public_key()."""

    # ── Valid keys ──────────────────────────────────────────────────────────
    def _ed25519_key(self):
        return (
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@host"
        )

    def _rsa_key(self):
        return (
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC2a+lots+ofbase64data"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA test@host"
        )

    def test_valid_ed25519_key(self):
        self.assertTrue(validate_ssh_public_key(self._ed25519_key()))

    def test_valid_rsa_key(self):
        # Minimal RSA key body that decodes to ≥16 bytes
        body = base64.b64encode(b"\x00" * 32).decode()
        key = f"ssh-rsa {body} test@host"
        self.assertTrue(validate_ssh_public_key(key))

    def test_valid_ecdsa_nistp256_key(self):
        body = base64.b64encode(b"\x00" * 32).decode()
        key = f"ecdsa-sha2-nistp256 {body} test@host"
        self.assertTrue(validate_ssh_public_key(key))

    def test_valid_ecdsa_nistp384_key(self):
        body = base64.b64encode(b"\x00" * 32).decode()
        key = f"ecdsa-sha2-nistp384 {body} test@host"
        self.assertTrue(validate_ssh_public_key(key))

    def test_valid_ecdsa_nistp521_key(self):
        body = base64.b64encode(b"\x00" * 32).decode()
        key = f"ecdsa-sha2-nistp521 {body} test@host"
        self.assertTrue(validate_ssh_public_key(key))

    def test_key_with_windows_line_endings(self):
        """CRLF files produced on Windows should still be valid."""
        body = base64.b64encode(b"\x00" * 32).decode()
        key = f"ssh-ed25519 {body} test@host\r\n"
        self.assertTrue(validate_ssh_public_key(key))

    def test_key_with_leading_trailing_whitespace(self):
        body = base64.b64encode(b"\x00" * 32).decode()
        key = f"  ssh-ed25519 {body} test@host  "
        self.assertTrue(validate_ssh_public_key(key))

    def test_key_with_comment_containing_spaces(self):
        body = base64.b64encode(b"\x00" * 32).decode()
        key = f"ssh-ed25519 {body} user name with spaces"
        self.assertTrue(validate_ssh_public_key(key))

    # ── Invalid keys ────────────────────────────────────────────────────────
    def test_empty_string(self):
        self.assertFalse(validate_ssh_public_key(""))

    def test_none_input(self):
        self.assertFalse(validate_ssh_public_key(None))  # type: ignore[arg-type]

    def test_only_whitespace(self):
        self.assertFalse(validate_ssh_public_key("   \n\t  "))

    def test_invalid_key_type(self):
        body = base64.b64encode(b"\x00" * 32).decode()
        self.assertFalse(validate_ssh_public_key(f"ssh-faketype {body} test@host"))

    def test_invalid_base64(self):
        self.assertFalse(validate_ssh_public_key("ssh-ed25519 not!!valid@base64 test@host"))

    def test_too_short_key_body(self):
        body = base64.b64encode(b"\x00" * 4).decode()  # Only 4 bytes
        self.assertFalse(validate_ssh_public_key(f"ssh-ed25519 {body} test@host"))

    def test_only_key_type_no_data(self):
        self.assertFalse(validate_ssh_public_key("ssh-ed25519"))

    def test_comment_too_long(self):
        body = base64.b64encode(b"\x00" * 32).decode()
        long_comment = "x" * 300
        key = f"ssh-ed25519 {body} {long_comment}"
        self.assertFalse(validate_ssh_public_key(key))

    def test_private_key_rejected(self):
        private_key = (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "b3BlbnNzaC1rZXktdjEAAAAA...\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        )
        self.assertFalse(validate_ssh_public_key(private_key))


class TestAddAuthorizedKey(unittest.TestCase):
    """Tests for add_authorized_key()."""

    def _make_fake_user(self, home_dir: str, username: str = "testuser"):
        """Return a mock pwd.struct_passwd-like object."""
        user = MagicMock()
        user.pw_dir = home_dir
        user.pw_uid = os.getuid()
        user.pw_gid = os.getgid()
        return user

    def _sample_key(self) -> str:
        body = base64.b64encode(b"\x00" * 32).decode()
        return f"ssh-ed25519 {body} test@host"

    def test_creates_ssh_dir_and_authorized_keys(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_user = self._make_fake_user(tmpdir)
            with patch("key_handler.pwd.getpwnam", return_value=fake_user):
                result = add_authorized_key("testuser", self._sample_key())

            self.assertIn("successfully", result.lower())
            ssh_dir = os.path.join(tmpdir, ".ssh")
            auth_keys = os.path.join(ssh_dir, "authorized_keys")

            self.assertTrue(os.path.isdir(ssh_dir))
            self.assertTrue(os.path.isfile(auth_keys))

            # Permissions
            dir_mode = os.stat(ssh_dir).st_mode & 0o777
            self.assertEqual(dir_mode, 0o700)

            file_mode = os.stat(auth_keys).st_mode & 0o777
            self.assertEqual(file_mode, 0o600)

            # Content
            with open(auth_keys) as fh:
                content = fh.read()
            self.assertIn(self._sample_key().split()[1], content)

    def test_appends_to_existing_authorized_keys(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ssh_dir = os.path.join(tmpdir, ".ssh")
            os.makedirs(ssh_dir, mode=0o700)
            existing_body = base64.b64encode(b"\x01" * 32).decode()
            existing_key = f"ssh-ed25519 {existing_body} existing@host\n"

            auth_keys_path = os.path.join(ssh_dir, "authorized_keys")
            with open(auth_keys_path, "w") as fh:
                fh.write(existing_key)
            os.chmod(auth_keys_path, 0o600)

            fake_user = self._make_fake_user(tmpdir)
            with patch("key_handler.pwd.getpwnam", return_value=fake_user):
                add_authorized_key("testuser", self._sample_key())

            with open(auth_keys_path) as fh:
                content = fh.read()

            # Both keys should be present
            self.assertIn(existing_body, content)
            self.assertIn(self._sample_key().split()[1], content)

    def test_does_not_add_duplicate_key(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ssh_dir = os.path.join(tmpdir, ".ssh")
            os.makedirs(ssh_dir, mode=0o700)
            auth_keys_path = os.path.join(ssh_dir, "authorized_keys")
            key = self._sample_key()

            with open(auth_keys_path, "w") as fh:
                fh.write(key + "\n")
            os.chmod(auth_keys_path, 0o600)

            fake_user = self._make_fake_user(tmpdir)
            with patch("key_handler.pwd.getpwnam", return_value=fake_user):
                result = add_authorized_key("testuser", key)

            self.assertIn("already", result.lower())

            with open(auth_keys_path) as fh:
                lines = [l for l in fh.read().splitlines() if l.strip()]
            self.assertEqual(len(lines), 1)

    def test_duplicate_detection_ignores_comment_difference(self):
        """Same key type + body but different comment → still a duplicate."""
        body = base64.b64encode(b"\x00" * 32).decode()

        with tempfile.TemporaryDirectory() as tmpdir:
            ssh_dir = os.path.join(tmpdir, ".ssh")
            os.makedirs(ssh_dir, mode=0o700)
            auth_keys_path = os.path.join(ssh_dir, "authorized_keys")

            with open(auth_keys_path, "w") as fh:
                fh.write(f"ssh-ed25519 {body} original-comment\n")
            os.chmod(auth_keys_path, 0o600)

            fake_user = self._make_fake_user(tmpdir)
            with patch("key_handler.pwd.getpwnam", return_value=fake_user):
                result = add_authorized_key("testuser", f"ssh-ed25519 {body} different-comment")

            self.assertIn("already", result.lower())

    def test_raises_value_error_for_unknown_user(self):
        with patch("key_handler.pwd.getpwnam", side_effect=KeyError("nosuchuser")):
            with self.assertRaises(ValueError):
                add_authorized_key("nosuchuser", self._sample_key())

    def test_fixes_ssh_dir_permissions(self):
        """If .ssh already exists with wrong permissions, they are corrected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ssh_dir = os.path.join(tmpdir, ".ssh")
            os.makedirs(ssh_dir, mode=0o755)  # Wrong – should be 0o700

            fake_user = self._make_fake_user(tmpdir)
            with patch("key_handler.pwd.getpwnam", return_value=fake_user):
                add_authorized_key("testuser", self._sample_key())

            dir_mode = os.stat(ssh_dir).st_mode & 0o777
            self.assertEqual(dir_mode, 0o700)


if __name__ == "__main__":
    unittest.main()
