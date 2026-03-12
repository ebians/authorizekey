"""SSH public key validation and authorized_keys management."""

import base64
import logging
import os
import pwd
import re

logger = logging.getLogger(__name__)

VALID_KEY_TYPES = {
    "ssh-rsa",
    "ssh-dss",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-ed25519",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "sk-ssh-ed25519@openssh.com",
}

# Minimum number of bytes a decoded key body must have to be considered valid
_MIN_KEY_BYTES = 16

# Maximum length of the optional comment field (everything after the base64 data)
_MAX_COMMENT_LEN = 256


def validate_ssh_public_key(key_content: str) -> bool:
    """Return True if *key_content* contains a valid SSH public key line.

    Only the first non-blank, non-comment line is examined so that files
    with trailing newlines or Windows line-endings are accepted.
    """
    if not key_content or not isinstance(key_content, str):
        return False

    for raw_line in key_content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split(None, 2)  # [type, base64data, optional_comment]
        if len(parts) < 2:
            return False

        key_type, key_data = parts[0], parts[1]
        comment = parts[2] if len(parts) == 3 else ""

        if key_type not in VALID_KEY_TYPES:
            return False

        # Validate base64 payload
        try:
            decoded = base64.b64decode(key_data, validate=True)
        except Exception:
            return False

        if len(decoded) < _MIN_KEY_BYTES:
            return False

        # Reject suspiciously long comments (guard against data stuffed there)
        if len(comment) > _MAX_COMMENT_LEN:
            return False

        return True  # First valid-looking key line found → accept

    return False


def add_authorized_key(username: str, key_content: str) -> str:
    """Append *key_content* to the authorized_keys file of *username*.

    Creates ``~/.ssh`` with mode 0o700 and ``authorized_keys`` with mode
    0o600 if they do not already exist.  Ownership is set to *username*.

    Returns a human-readable status string.

    Raises:
        ValueError: user does not exist on the system.
        PermissionError: the process lacks the required OS privileges.
    """
    key_line = key_content.strip()

    # Resolve the Linux user
    try:
        user_info = pwd.getpwnam(username)
    except KeyError as exc:
        raise ValueError(f"User '{username}' does not exist on this system") from exc

    home_dir = user_info.pw_dir
    uid = user_info.pw_uid
    gid = user_info.pw_gid

    ssh_dir = os.path.join(home_dir, ".ssh")
    authorized_keys_path = os.path.join(ssh_dir, "authorized_keys")

    # ------------------------------------------------------------------
    # Create / fix ~/.ssh
    # ------------------------------------------------------------------
    if not os.path.exists(ssh_dir):
        os.makedirs(ssh_dir, mode=0o700)
        os.chown(ssh_dir, uid, gid)
        logger.info("Created %s", ssh_dir)
    else:
        current_mode = os.stat(ssh_dir).st_mode & 0o777
        if current_mode != 0o700:
            os.chmod(ssh_dir, 0o700)
            logger.info("Fixed permissions on %s", ssh_dir)

    # ------------------------------------------------------------------
    # Duplicate check (compare key-type + base64 body; ignore comment)
    # ------------------------------------------------------------------
    new_parts = key_line.split(None, 2)

    if os.path.exists(authorized_keys_path):
        with open(authorized_keys_path, "r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                existing_parts = stripped.split(None, 2)
                if (
                    len(existing_parts) >= 2
                    and len(new_parts) >= 2
                    and existing_parts[0] == new_parts[0]
                    and existing_parts[1] == new_parts[1]
                ):
                    return "Key already present in authorized_keys (no change made)"

    # ------------------------------------------------------------------
    # Append the new key
    # ------------------------------------------------------------------
    with open(authorized_keys_path, "a", encoding="utf-8") as fh:
        fh.write(key_line + "\n")

    # Ensure correct permissions and ownership
    os.chmod(authorized_keys_path, 0o600)
    os.chown(authorized_keys_path, uid, gid)

    logger.info("Added key for user '%s' to %s", username, authorized_keys_path)
    return "Key successfully added to authorized_keys"
