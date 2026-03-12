"""Integration tests for the Flask application routes."""

import base64
import io
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Disable secure cookie flag for testing (no HTTPS in test client)
os.environ.setdefault("HTTPS", "false")
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production")

import app as app_module  # noqa: E402


def _make_valid_key():
    body = base64.b64encode(b"\x00" * 32).decode()
    return f"ssh-ed25519 {body} test@host"


class TestLoginRoutes(unittest.TestCase):
    def setUp(self):
        app_module.app.config["TESTING"] = True
        app_module.app.config["WTF_CSRF_ENABLED"] = False
        self.client = app_module.app.test_client()

    def test_index_redirects_to_login(self):
        rv = self.client.get("/", follow_redirects=False)
        self.assertEqual(rv.status_code, 302)
        self.assertIn("/login", rv.headers["Location"])

    def test_login_page_renders(self):
        rv = self.client.get("/login")
        self.assertEqual(rv.status_code, 200)
        self.assertIn(b"AuthorizeKey", rv.data)
        self.assertIn(b"username", rv.data.lower())

    def test_login_success_redirects_to_upload(self):
        with patch("app.authenticate", return_value=True):
            rv = self.client.post(
                "/login",
                data={"username": "alice", "password": "secret"},
                follow_redirects=False,
            )
        self.assertEqual(rv.status_code, 302)
        self.assertIn("/upload", rv.headers["Location"])

    def test_login_failure_shows_error(self):
        with patch("app.authenticate", return_value=False):
            rv = self.client.post(
                "/login",
                data={"username": "alice", "password": "wrong"},
                follow_redirects=True,
            )
        self.assertEqual(rv.status_code, 200)
        self.assertIn(b"Invalid", rv.data)

    def test_login_already_logged_in_redirects_to_upload(self):
        with self.client.session_transaction() as sess:
            sess["username"] = "alice"
        rv = self.client.get("/login", follow_redirects=False)
        self.assertEqual(rv.status_code, 302)
        self.assertIn("/upload", rv.headers["Location"])


class TestUploadRoute(unittest.TestCase):
    def setUp(self):
        app_module.app.config["TESTING"] = True
        app_module.app.config["WTF_CSRF_ENABLED"] = False
        self.client = app_module.app.test_client()

    def _login(self, username="alice"):
        with self.client.session_transaction() as sess:
            sess["username"] = username

    def test_upload_page_requires_auth(self):
        rv = self.client.get("/upload", follow_redirects=False)
        self.assertEqual(rv.status_code, 302)
        self.assertIn("/login", rv.headers["Location"])

    def test_upload_page_renders_when_authenticated(self):
        self._login()
        rv = self.client.get("/upload")
        self.assertEqual(rv.status_code, 200)
        self.assertIn(b"authorized_keys", rv.data.lower())

    def test_logout_clears_session(self):
        self._login()
        rv = self.client.post("/logout", follow_redirects=False)
        self.assertEqual(rv.status_code, 302)
        self.assertIn("/login", rv.headers["Location"])
        with self.client.session_transaction() as sess:
            self.assertNotIn("username", sess)


class TestUploadKeyApi(unittest.TestCase):
    def setUp(self):
        app_module.app.config["TESTING"] = True
        app_module.app.config["WTF_CSRF_ENABLED"] = False
        self.client = app_module.app.test_client()

    def _login(self, username="alice"):
        with self.client.session_transaction() as sess:
            sess["username"] = username

    def _post_key(self, key_content: str, filename: str = "id_ed25519.pub"):
        data = {
            "keyfile": (io.BytesIO(key_content.encode()), filename),
        }
        return self.client.post(
            "/api/upload-key",
            data=data,
            content_type="multipart/form-data",
        )

    def test_returns_401_without_session(self):
        rv = self._post_key(_make_valid_key())
        self.assertEqual(rv.status_code, 401)

    def test_returns_400_with_no_file(self):
        self._login()
        rv = self.client.post("/api/upload-key", data={}, content_type="multipart/form-data")
        self.assertEqual(rv.status_code, 400)

    def test_returns_400_for_invalid_key(self):
        self._login()
        rv = self._post_key("this is not a key")
        self.assertEqual(rv.status_code, 400)
        self.assertIn(b"valid SSH", rv.data)

    def test_returns_400_for_empty_file(self):
        self._login()
        rv = self._post_key("")
        self.assertEqual(rv.status_code, 400)

    def test_successful_key_upload(self):
        self._login()
        with patch("app.add_authorized_key", return_value="Key successfully added to authorized_keys"):
            rv = self._post_key(_make_valid_key())
        self.assertEqual(rv.status_code, 200)
        json_data = rv.get_json()
        self.assertTrue(json_data["success"])
        self.assertIn("successfully", json_data["message"].lower())

    def test_returns_500_on_permission_error(self):
        self._login()
        with patch("app.add_authorized_key", side_effect=PermissionError("denied")):
            rv = self._post_key(_make_valid_key())
        self.assertEqual(rv.status_code, 500)

    def test_returns_400_on_value_error(self):
        self._login()
        with patch("app.add_authorized_key", side_effect=ValueError("no such user")):
            rv = self._post_key(_make_valid_key())
        self.assertEqual(rv.status_code, 400)

    def test_binary_file_returns_400(self):
        self._login()
        binary_data = b"\xff\xfe\x00\x01binary"
        data = {"keyfile": (io.BytesIO(binary_data), "key.pub")}
        rv = self.client.post(
            "/api/upload-key",
            data=data,
            content_type="multipart/form-data",
        )
        self.assertEqual(rv.status_code, 400)


if __name__ == "__main__":
    unittest.main()
