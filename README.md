# AuthorizeKey

A secure Python web application that lets Windows clients drag-and-drop SSH
public keys to a Linux server, automatically adding them to the authenticated
user's `~/.ssh/authorized_keys`.

## Screenshots

### Login page

![Login page](https://github.com/user-attachments/assets/b800e86b-3b95-46e8-88f9-94791fe1aaba)

### Upload page

![Upload page](https://github.com/user-attachments/assets/7c0497a8-8aa1-4ee6-b67e-ee96232d6b1f)

---

## Features

| Feature | Details |
|---------|---------|
| **Linux user authentication** | PAM – the same credentials used to log in to the server |
| **Drag-and-drop upload** | Drop a `.pub` file onto the browser window; no command-line needed |
| **Key validation** | Client- *and* server-side checks; only valid OpenSSH public-key formats are accepted |
| **Duplicate detection** | The same key body is never written twice |
| **Correct file permissions** | `~/.ssh` → `0700`, `authorized_keys` → `0600`, ownership set to the target user |
| **CSRF protection** | Flask-WTF CSRF tokens on every form and XHR request |
| **Security headers** | Caddy / Nginx add HSTS, X-Frame-Options, CSP, etc. |
| **Upload size limit** | 16 KB hard cap in the WSGI layer |
| **Reverse proxy** | Caddy (preferred) or Nginx; both configs are provided |

---

## Architecture

```
Browser (Windows client)
        │  HTTPS
        ▼
  Caddy / Nginx          ← TLS termination + security headers
        │  HTTP (loopback only)
        ▼
  Gunicorn + Flask       ← WSGI server + application logic
        │
        ├── auth.py        ← PAM authentication
        ├── key_handler.py ← SSH key validation & authorized_keys management
        └── templates/     ← Login + Upload UI
```

---

## Requirements

- Python ≥ 3.10
- Linux with PAM (`libpam-dev` on Debian/Ubuntu)
- Caddy **or** Nginx
- Root or equivalent privileges (needed to write to arbitrary users' `~/.ssh`)

---

## Quick Start

### 1 – Install Python dependencies

```bash
python3 -m venv /opt/authorizekey/venv
source /opt/authorizekey/venv/bin/activate
pip install -r requirements.txt
```

### 2 – Set environment variables

Create `/etc/authorizekey/env` (mode `0600`, owner `root`):

```
SECRET_KEY=<output of: python3 -c "import secrets; print(secrets.token_hex(32))">
HTTPS=true
```

### 3 – Deploy with Gunicorn as a systemd service

```bash
cp authorizekey.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now authorizekey
```

### 4 – Configure the web server

**Caddy** (recommended – automatic HTTPS):

```bash
# Edit Caddyfile: replace "your-server-hostname" with your domain or IP
cp Caddyfile /etc/caddy/Caddyfile
systemctl reload caddy
```

**Nginx** (alternative):

```bash
# Edit nginx.conf and replace "your-server-hostname"
cp nginx.conf /etc/nginx/sites-available/authorizekey
ln -s /etc/nginx/sites-available/authorizekey \
      /etc/nginx/sites-enabled/authorizekey
nginx -t && systemctl reload nginx
```

---

## Usage

1. Open a browser and navigate to `https://your-server-hostname`
2. Log in with your Linux username and password
3. Drag and drop your `id_ed25519.pub` (or any OpenSSH `.pub` file) onto the
   upload area – or click to browse
4. Click **Add to authorized_keys**
5. The key is appended to `~/.ssh/authorized_keys` on the server

---

## Security Notes

| Concern | Mitigation |
|---------|-----------|
| Credential theft | All traffic is HTTPS; session cookies are `HttpOnly`, `Secure`, `SameSite=Lax` |
| Key injection | Server validates every key with `base64.b64decode(validate=True)` + key-type allow-list |
| Path traversal | Home directory is resolved via `pwd.getpwnam()`, never from user input |
| CSRF | `Flask-WTF` generates and validates tokens for every state-changing request |
| Username injection | Regex `^[a-z_][a-z0-9_-]{0,31}$` is enforced before any PAM call |
| Excessive upload size | `MAX_CONTENT_LENGTH = 16 KB` enforced at the WSGI layer |
| Duplicate keys | Key type + base64 body are compared; comment differences are ignored |

> **Note:** The application must run as `root` (or a user with write access to
> all home directories) to be able to modify arbitrary users' `authorized_keys`
> files.  The systemd unit file is hardened with `ProtectSystem=strict`,
> `PrivateTmp=true`, and `NoNewPrivileges=true` to reduce the blast radius.

---

## Running Tests

```bash
pip install pytest
python3 -m pytest tests/ -v
```

---

## File Structure

```
authorizekey/
├── app.py                  # Flask application (routes, sessions, CSRF)
├── auth.py                 # PAM authentication helper
├── key_handler.py          # SSH key validation & authorized_keys management
├── requirements.txt        # Python dependencies
├── Caddyfile               # Caddy reverse-proxy configuration
├── nginx.conf              # Nginx reverse-proxy configuration (alternative)
├── authorizekey.service    # systemd service unit
├── templates/
│   ├── login.html          # Login page
│   └── upload.html         # Drag-and-drop upload page
├── static/
│   └── style.css           # Stylesheet
└── tests/
    ├── test_app.py         # Flask route integration tests
    ├── test_auth.py        # Authentication unit tests
    └── test_key_handler.py # Key validation & file-handling unit tests
```