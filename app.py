"""Flask web application for SSH public-key transfer.

Users authenticate with their Linux credentials (via PAM) and then
drag-and-drop their SSH public-key file to add it to their
~/.ssh/authorized_keys on the server.
"""

import logging
import os

from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import PasswordField, StringField
from wtforms.validators import DataRequired

from auth import authenticate
from key_handler import add_authorized_key, validate_ssh_public_key

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------
app = Flask(__name__)

# SECRET_KEY must be set via environment variable in production.
# Falling back to urandom makes every server restart invalidate existing
# sessions, which is acceptable for this tool.
_secret = os.environ.get("SECRET_KEY")
if not _secret:
    logger.warning(
        "SECRET_KEY env var not set – generating a random key. "
        "Sessions will not survive restarts."
    )
    _secret = os.urandom(32)
app.config["SECRET_KEY"] = _secret

# Limit upload size to 16 KB – more than enough for any SSH public key file.
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

# Session cookie hardening
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# SECURE flag: disable only when explicitly running without TLS (dev mode)
_https = os.environ.get("HTTPS", "true").lower()
app.config["SESSION_COOKIE_SECURE"] = _https not in ("false", "0", "no")

csrf = CSRFProtect(app)

# ---------------------------------------------------------------------------
# Forms
# ---------------------------------------------------------------------------


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.route("/")
def index():
    if "username" in session:
        return redirect(url_for("upload"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if "username" in session:
        return redirect(url_for("upload"))

    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        if authenticate(username, password):
            session["username"] = username
            logger.info("User '%s' authenticated successfully", username)
            return redirect(url_for("upload"))

        flash("Invalid username or password.", "error")
        logger.warning("Failed login attempt for user: %s", username)

    return render_template("login.html", form=form)


@app.route("/logout", methods=["POST"])
def logout():
    username = session.pop("username", None)
    if username:
        logger.info("User '%s' logged out", username)
    return redirect(url_for("login"))


@app.route("/upload")
def upload():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("upload.html", username=session["username"])


@app.route("/api/upload-key", methods=["POST"])
def upload_key():
    """Accept an SSH public key file and add it to authorized_keys."""
    if "username" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    if "keyfile" not in request.files:
        return jsonify({"error": "No file part in the request"}), 400

    file = request.files["keyfile"]

    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    # Decode file content
    try:
        key_content = file.read().decode("utf-8")
    except UnicodeDecodeError:
        return jsonify({"error": "File must be plain text (UTF-8)"}), 400

    key_content = key_content.strip()
    if not key_content:
        return jsonify({"error": "The uploaded file is empty"}), 400

    # Validate SSH public key format
    if not validate_ssh_public_key(key_content):
        return jsonify({"error": "The file does not contain a valid SSH public key"}), 400

    username = session["username"]
    try:
        message = add_authorized_key(username, key_content)
        logger.info("Key operation for '%s': %s", username, message)
        return jsonify({"success": True, "message": message})
    except ValueError as exc:
        logger.error("Key operation failed for '%s': %s", username, exc)
        return jsonify({"error": str(exc)}), 400
    except PermissionError as exc:
        logger.error("Permission error for '%s': %s", username, exc)
        return jsonify({"error": "Permission denied writing to key file"}), 500
    except Exception as exc:  # noqa: BLE001
        logger.error("Unexpected error for '%s': %s", username, exc)
        return jsonify({"error": "Internal server error"}), 500


# ---------------------------------------------------------------------------
# Entry point (dev only – use gunicorn in production)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=int(os.environ.get("PORT", "5000")),
        debug=False,
    )
