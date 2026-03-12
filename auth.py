"""Linux PAM-based authentication helpers."""

import logging
import re

logger = logging.getLogger(__name__)

# POSIX-portable username pattern: starts with lowercase letter or underscore,
# followed by at most 31 lowercase alphanumerics, underscores, or hyphens.
_USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


def is_valid_username(username: str) -> bool:
    """Return True if *username* matches the allowed POSIX username pattern."""
    return bool(username and _USERNAME_RE.match(username))


def authenticate(username: str, password: str) -> bool:
    """Authenticate a Linux user via PAM.

    Returns True on success, False on failure.  Invalid inputs are rejected
    before any PAM call is made to prevent injection attacks.
    """
    if not is_valid_username(username):
        logger.warning("Rejected login attempt with invalid username format")
        return False

    if not password:
        return False

    try:
        import pam  # type: ignore[import]

        p = pam.pam()
        result = p.authenticate(username, password)
        if not result:
            logger.warning("PAM authentication failed for user: %s", username)
        return result
    except ImportError:
        logger.error("python-pam is not installed; authentication unavailable")
        return False
    except Exception as exc:  # noqa: BLE001
        logger.error("PAM authentication raised an exception: %s", exc)
        return False
