"""Unit tests for the auth module."""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auth import authenticate, is_valid_username  # noqa: E402


class TestIsValidUsername(unittest.TestCase):
    def test_valid_simple(self):
        self.assertTrue(is_valid_username("alice"))

    def test_valid_with_numbers(self):
        self.assertTrue(is_valid_username("user123"))

    def test_valid_with_hyphen(self):
        self.assertTrue(is_valid_username("my-user"))

    def test_valid_with_underscore_prefix(self):
        self.assertTrue(is_valid_username("_svc"))

    def test_invalid_empty(self):
        self.assertFalse(is_valid_username(""))

    def test_invalid_none(self):
        self.assertFalse(is_valid_username(None))  # type: ignore[arg-type]

    def test_invalid_starts_with_digit(self):
        self.assertFalse(is_valid_username("1admin"))

    def test_invalid_uppercase(self):
        self.assertFalse(is_valid_username("Admin"))

    def test_invalid_too_long(self):
        self.assertFalse(is_valid_username("a" * 33))

    def test_invalid_special_chars(self):
        self.assertFalse(is_valid_username("user; rm -rf"))

    def test_invalid_dot(self):
        self.assertFalse(is_valid_username("user.name"))

    def test_invalid_path_traversal(self):
        self.assertFalse(is_valid_username("../etc"))


class TestAuthenticate(unittest.TestCase):
    def _mock_pam(self, result: bool):
        pam_instance = MagicMock()
        pam_instance.authenticate.return_value = result
        pam_module = MagicMock()
        pam_module.pam.return_value = pam_instance
        return pam_module

    def test_successful_authentication(self):
        with patch.dict("sys.modules", {"pam": self._mock_pam(True)}):
            self.assertTrue(authenticate("alice", "correctpassword"))

    def test_failed_authentication(self):
        with patch.dict("sys.modules", {"pam": self._mock_pam(False)}):
            self.assertFalse(authenticate("alice", "wrongpassword"))

    def test_invalid_username_rejected_before_pam(self):
        """PAM should never be called for an invalid username."""
        pam_module = self._mock_pam(True)
        with patch.dict("sys.modules", {"pam": pam_module}):
            result = authenticate("bad user!", "password")
        self.assertFalse(result)
        pam_module.pam.assert_not_called()

    def test_empty_password_rejected(self):
        pam_module = self._mock_pam(True)
        with patch.dict("sys.modules", {"pam": pam_module}):
            result = authenticate("alice", "")
        self.assertFalse(result)
        pam_module.pam.assert_not_called()

    def test_empty_username_rejected(self):
        self.assertFalse(authenticate("", "password"))

    def test_pam_import_error_returns_false(self):
        with patch.dict("sys.modules", {"pam": None}):
            result = authenticate("alice", "password")
        self.assertFalse(result)

    def test_pam_exception_returns_false(self):
        pam_module = MagicMock()
        pam_module.pam.side_effect = Exception("PAM exploded")
        with patch.dict("sys.modules", {"pam": pam_module}):
            result = authenticate("alice", "password")
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
