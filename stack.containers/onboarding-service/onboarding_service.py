#!/usr/bin/env python3
import hmac
import html
import hashlib
import json
import os
import re
import secrets
import string
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib import request, error

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,160}$")
CSS_TOKEN_RE = re.compile(r"^[A-Za-z0-9#(),.% -]{1,80}$")


def env(name: str, default: str = "") -> str:
    value = os.environ.get(name, default).strip()
    if not value and default == "":
        raise RuntimeError(f"missing required environment variable: {name}")
    return value


def css_env(name: str, default: str) -> str:
    value = os.environ.get(name, default).strip()
    return value if CSS_TOKEN_RE.fullmatch(value) else default


DOMAIN = env("DOMAIN")
TRUSTED_PROXY_SECRET = env("ONBOARDING_TRUSTED_PROXY_SECRET")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "webservices").strip() or "webservices"
KEYCLOAK_INTERNAL_URL = os.environ.get("KEYCLOAK_INTERNAL_URL", "http://keycloak:8080").rstrip("/")
KEYCLOAK_ADMIN_USER = os.environ.get("KEYCLOAK_ADMIN_USER", "admin").strip()
KEYCLOAK_ADMIN_PASSWORD = os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "").strip()
SELF_SERVICE_ENABLED = os.environ.get("ONBOARDING_SELF_SERVICE_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}
INVITES_JSON = os.environ.get("ONBOARDING_INVITES_JSON", "[]").strip() or "[]"
STATE_PATH = Path(os.environ.get("ONBOARDING_STATE_PATH", "/data/onboarding-state.json"))
METHOD_ACTIONS = {
    "password": "UPDATE_PASSWORD",
    "totp": "CONFIGURE_TOTP",
}


class ProxyAuthError(Exception):
    pass


def require_valid_username(username: str) -> str:
    username = username.strip()
    if not USERNAME_RE.fullmatch(username):
        raise ValueError("authenticated username is missing or invalid")
    return username


def split_groups(value: str | None) -> set[str]:
    if not value:
        return set()
    return {part.strip() for part in re.split(r"[,;]", value) if part.strip()}


def keycloak_account_url() -> str:
    return f"https://keycloak.{DOMAIN}/realms/{KEYCLOAK_REALM}/account/"


def home_url() -> str:
    return f"https://homepage.{DOMAIN}/"


def onboarding_start_url() -> str:
    return f"https://onboarding.{DOMAIN}/start"


def load_invites(raw: str = INVITES_JSON) -> list[dict]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"ONBOARDING_INVITES_JSON is not valid JSON: {exc}") from exc
    if not isinstance(data, list):
        raise RuntimeError("ONBOARDING_INVITES_JSON must be a JSON array")
    return data


def invite_code_matches(invite: dict, code: str) -> bool:
    if not code:
        return False
    expected = str(invite.get("code", ""))
    expected_hash = str(invite.get("codeHash", ""))
    if expected and hmac.compare_digest(expected, code):
        return True
    if expected_hash:
        digest = hashlib.sha256(code.encode("utf-8")).hexdigest()
        return hmac.compare_digest(expected_hash, digest)
    return False


def normalize_csv(value: object) -> list[str]:
    if isinstance(value, list):
        raw = value
    elif isinstance(value, str):
        raw = re.split(r"[,;\s]+", value)
    else:
        raw = []
    result = []
    for item in raw:
        text = str(item).strip()
        if text and text not in result:
            result.append(text)
    return result


def required_actions_for_methods(methods: list[str]) -> list[str]:
    actions = []
    for method in methods:
        action = METHOD_ACTIONS.get(method)
        if not action:
            raise ValueError(f"unsupported onboarding method: {method}")
        if action not in actions:
            actions.append(action)
    return actions


def find_invite(code: str) -> dict | None:
    for invite in load_invites():
        if invite_code_matches(invite, code):
            return invite
    return None


def load_state() -> dict:
    try:
        with STATE_PATH.open("r", encoding="utf-8") as handle:
            state = json.load(handle)
            return state if isinstance(state, dict) else {}
    except FileNotFoundError:
        return {}


def save_state(state: dict) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = STATE_PATH.with_suffix(".tmp")
    with tmp_path.open("w", encoding="utf-8") as handle:
        json.dump(state, handle, sort_keys=True)
    tmp_path.replace(STATE_PATH)


def invite_key(invite: dict) -> str:
    if invite.get("id"):
        return str(invite["id"])
    if invite.get("codeHash"):
        return "sha256:" + str(invite["codeHash"])
    return "code:" + hashlib.sha256(str(invite.get("code", "")).encode("utf-8")).hexdigest()


def assert_invite_available(invite: dict, email: str) -> None:
    state = load_state()
    key = invite_key(invite)
    max_uses = int(invite.get("maxUses", 1))
    used = int(state.get("inviteUses", {}).get(key, 0))
    if used >= max_uses:
        raise ValueError("invite has already been used")

    domains = normalize_csv(invite.get("emailDomains"))
    if domains:
        email_domain = email.rsplit("@", 1)[-1].lower() if "@" in email else ""
        if email_domain not in [domain.lower() for domain in domains]:
            raise ValueError("email domain is not allowed by this invite")

    allowed_emails = [item.lower() for item in normalize_csv(invite.get("emails"))]
    if allowed_emails and email.lower() not in allowed_emails:
        raise ValueError("email is not allowed by this invite")


def mark_invite_used(invite: dict) -> None:
    state = load_state()
    uses = state.setdefault("inviteUses", {})
    key = invite_key(invite)
    uses[key] = int(uses.get(key, 0)) + 1
    save_state(state)


def generate_temp_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "-".join("".join(secrets.choice(alphabet) for _ in range(6)) for _ in range(4))


def keycloak_token() -> str:
    if not KEYCLOAK_ADMIN_PASSWORD:
        raise RuntimeError("self-service onboarding is not configured with Keycloak admin credentials")
    body = urllib.parse.urlencode({
        "grant_type": "password",
        "client_id": "admin-cli",
        "username": KEYCLOAK_ADMIN_USER,
        "password": KEYCLOAK_ADMIN_PASSWORD,
    }).encode("utf-8")
    response = request.urlopen(
        request.Request(
            f"{KEYCLOAK_INTERNAL_URL}/realms/master/protocol/openid-connect/token",
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        ),
        timeout=15,
    )
    payload = json.loads(response.read().decode("utf-8"))
    return payload["access_token"]


def keycloak_admin_request(method: str, path: str, token: str, payload: dict | None = None):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Authorization": f"Bearer {token}"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    return request.urlopen(
        request.Request(f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}{path}", data=data, headers=headers, method=method),
        timeout=15,
    )


def create_keycloak_user(username: str, email: str, invite: dict) -> tuple[str, str, list[str], list[str]]:
    groups = normalize_csv(invite.get("groups")) or ["users"]
    if "users" not in groups:
        groups.insert(0, "users")
    methods = normalize_csv(invite.get("methods")) or ["password", "totp"]
    required_actions = required_actions_for_methods(methods)
    temp_password = generate_temp_password()
    token = keycloak_token()
    user_payload = {
        "username": username,
        "email": email,
        "enabled": True,
        "emailVerified": False,
        "groups": [group if group.startswith("/") else f"/{group}" for group in groups],
        "requiredActions": required_actions,
        "credentials": [{
            "type": "password",
            "value": temp_password,
            "temporary": True,
        }],
    }
    try:
        response = keycloak_admin_request("POST", "/users", token, user_payload)
    except error.HTTPError as exc:
        if exc.code == 409:
            raise ValueError("that username or email already exists") from exc
        raise
    location = response.headers.get("Location", "")
    user_id = location.rstrip("/").rsplit("/", 1)[-1] if location else username
    return user_id, temp_password, groups, required_actions


def render_start_page(message: str = "") -> str:
    disabled = "" if SELF_SERVICE_ENABLED else "disabled"
    notice = html.escape(message or ("Self-service onboarding is enabled." if SELF_SERVICE_ENABLED else "Self-service onboarding is not enabled for this stack."))
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Start account onboarding</title>
  <style>
    :root {{ color-scheme: dark; --bg:{css_env("THEME_BACKGROUND", "#111827")}; --panel:{css_env("THEME_SURFACE", "#1f2937")}; --line:{css_env("THEME_LINE", "#334155")}; --ink:{css_env("THEME_TEXT", "#f4f7f6")}; --muted:{css_env("THEME_MUTED", "#a7b0b8")}; --primary:{css_env("THEME_PRIMARY", "#14b8a6")}; --accent:{css_env("THEME_ACCENT", "#f97316")}; }}
    body {{ margin:0; min-height:100vh; font:16px/1.5 ui-sans-serif, system-ui, sans-serif; color:var(--ink); background:linear-gradient(135deg,#071012,var(--bg)); display:grid; place-items:center; }}
    main {{ width:min(92vw,42rem); background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:2rem; }}
    label {{ display:block; margin-top:1rem; color:var(--muted); }}
    input {{ box-sizing:border-box; width:100%; margin-top:.35rem; padding:.85rem; border-radius:8px; border:1px solid var(--line); background:#0b1215; color:var(--ink); }}
    button {{ margin-top:1.2rem; border:0; border-radius:999px; padding:.85rem 1.2rem; background:var(--primary); color:#061313; font-weight:800; }}
    p {{ color:var(--muted); }}
    .error {{ color:var(--accent); }}
  </style>
</head>
<body>
  <main>
    <h1>Start account onboarding</h1>
    <p class="{"error" if message else ""}">{notice}</p>
    <form method="post" action="/api/invites/signup">
      <label>Invite code <input {disabled} required name="code" autocomplete="one-time-code"></label>
      <label>Username <input {disabled} required name="username" autocomplete="username" pattern="[A-Za-z0-9_.@-]{{1,160}}"></label>
      <label>Email <input {disabled} required name="email" type="email" autocomplete="email"></label>
      <button {disabled} type="submit">Create account</button>
    </form>
  </main>
</body>
</html>"""


def render_signup_result(username: str, email: str, temp_password: str, groups: list[str], required_actions: list[str]) -> str:
    return f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Account created</title></head>
<body style="margin:0;min-height:100vh;display:grid;place-items:center;background:#071012;color:#f4f7f6;font:16px system-ui">
  <main style="width:min(92vw,42rem);background:#1f2937;border:1px solid #334155;border-radius:8px;padding:2rem">
    <h1>Account created</h1>
    <p>User <code>{html.escape(username)}</code> is ready for Keycloak setup.</p>
    <p>Email: <code>{html.escape(email)}</code></p>
    <p>Groups: <code>{html.escape(", ".join(groups))}</code></p>
    <p>Required actions: <code>{html.escape(", ".join(required_actions))}</code></p>
    <p>Temporary password, shown once:</p>
    <p style="font-size:1.25rem"><code>{html.escape(temp_password)}</code></p>
    <p>Use it in Keycloak, then update your password and enroll TOTP.</p>
    <a style="display:inline-block;background:#14b8a6;color:#061313;border-radius:999px;padding:.85rem 1.2rem;text-decoration:none;font-weight:800" href="{html.escape(keycloak_account_url())}">Open Keycloak account console</a>
  </main>
</body>
</html>"""


def render_page(username: str, groups: set[str], email: str | None) -> str:
    onboarding_required = "onboarding_required" in groups or "onboarding-required" in groups
    status = (
        "Keycloak required actions are pending for this account."
        if onboarding_required else
        "No onboarding marker is present. You can continue to the stack."
    )
    required = (
        "<li>Update the temporary password in Keycloak.</li>"
        "<li>Enroll OTP/MFA from the Keycloak account console.</li>"
        "<li>Return to the stack after Keycloak clears required actions.</li>"
    )
    group_list = ", ".join(sorted(groups)) if groups else "none"
    theme_background = css_env("THEME_BACKGROUND", "#111827")
    theme_background_alt = css_env("THEME_BACKGROUND_ALT", "#0b1215")
    theme_surface = css_env("THEME_SURFACE", "#1f2937")
    theme_surface_alt = css_env("THEME_SURFACE_ALT", "#18212f")
    theme_line = css_env("THEME_LINE", "#334155")
    theme_text = css_env("THEME_TEXT", "#f4f7f6")
    theme_muted = css_env("THEME_MUTED", "#a7b0b8")
    theme_primary = css_env("THEME_PRIMARY", "#14b8a6")
    theme_accent = css_env("THEME_ACCENT", "#f97316")
    theme_accent_text = css_env("THEME_ACCENT_TEXT", "#431407")
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Keycloak account onboarding</title>
  <style>
    :root {{ color-scheme: dark; --bg:{theme_background}; --bg-alt:{theme_background_alt}; --panel:{theme_surface}; --panel-alt:{theme_surface_alt}; --line:{theme_line}; --ink:{theme_text}; --muted:{theme_muted}; --primary:{theme_primary}; --accent:{theme_accent}; --accent-text:{theme_accent_text}; }}
    body {{ margin:0; min-height:100vh; font:16px/1.5 ui-sans-serif, system-ui, sans-serif; color:var(--ink); background:radial-gradient(circle at 20% 0%, color-mix(in srgb, var(--primary) 18%, transparent) 0, transparent 36rem), linear-gradient(135deg,var(--bg-alt),var(--bg)); display:grid; place-items:center; }}
    main {{ width:min(92vw, 54rem); background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:clamp(1.25rem, 4vw, 3rem); box-shadow:0 24px 80px #0009; }}
    h1 {{ margin:0 0 .4rem; font-size:clamp(2rem, 6vw, 4.25rem); line-height:1; letter-spacing:0; }}
    p, li {{ color:var(--muted); }}
    .card {{ border:1px solid var(--line); border-radius:8px; padding:1.2rem; background:var(--panel-alt); margin-top:1rem; }}
    .button {{ border:0; border-radius:999px; background:var(--primary); color:#061313; font-weight:900; padding:.85rem 1.1rem; margin:.6rem .5rem 0 0; text-decoration:none; display:inline-block; }}
    .button:hover {{ background:var(--accent); color:var(--accent-text); }}
    code {{ background:var(--bg-alt); border:1px solid var(--line); border-radius:8px; padding:.25rem .45rem; color:var(--primary); }}
  </style>
</head>
<body>
  <main>
    <h1>Finish account setup in Keycloak</h1>
    <p>{html.escape(status)}</p>
    <section class="card">
      <p><strong>User:</strong> <code>{html.escape(username)}</code></p>
      <p><strong>Email:</strong> <code>{html.escape(email or "unknown")}</code></p>
      <p><strong>Groups:</strong> <code>{html.escape(group_list)}</code></p>
    </section>
    <section class="card">
      <h2>Required actions</h2>
      <ol>{required}</ol>
      <a class="button" href="{html.escape(keycloak_account_url())}">Open Keycloak account console</a>
      <a class="button" href="{html.escape(home_url())}">Return to homepage</a>
    </section>
  </main>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "webservices-onboarding/2.0"

    def log_message(self, fmt: str, *args) -> None:
        print(f"[onboarding] {self.address_string()} {fmt % args}", flush=True)

    def require_trusted_proxy(self) -> None:
        provided = (self.headers.get("X-Trusted-Proxy-Secret") or "").strip()
        if not hmac.compare_digest(provided, TRUSTED_PROXY_SECRET):
            raise ProxyAuthError("request did not come through the trusted proxy")

    def current_user(self) -> str:
        username = self.headers.get("X-Remote-User") or ""
        return require_valid_username(username)

    def send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, body: str) -> None:
        encoded = body.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def read_form(self) -> dict[str, str]:
        content_length = int(self.headers.get("Content-Length", "0") or "0")
        if content_length > 16_384:
            raise ValueError("request body is too large")
        body = self.rfile.read(content_length).decode("utf-8") if content_length else ""
        content_type = self.headers.get("Content-Type", "")
        if content_type.startswith("application/json"):
            payload = json.loads(body or "{}")
            return {str(key): str(value).strip() for key, value in payload.items()}
        parsed = urllib.parse.parse_qs(body, keep_blank_values=True)
        return {key: values[0].strip() if values else "" for key, values in parsed.items()}

    def handle_error(self, error: Exception) -> None:
        status = HTTPStatus.FORBIDDEN if isinstance(error, ProxyAuthError) else HTTPStatus.BAD_REQUEST
        self.send_json(status, {"ok": False, "error": str(error)})

    def do_GET(self) -> None:
        try:
            if self.path == "/health":
                self.send_json(HTTPStatus.OK, {"ok": True})
                return
            self.require_trusted_proxy()
            if self.path == "/start" or self.path.startswith("/start?"):
                self.send_html(render_start_page())
                return
            username = self.current_user()
            groups = split_groups(self.headers.get("X-Remote-Groups"))
            email = self.headers.get("X-Remote-Email")
            if self.path == "/" or self.path.startswith("/?"):
                self.send_html(render_page(username, groups, email))
                return
            if self.path == "/api/status":
                self.send_json(HTTPStatus.OK, {
                    "ok": True,
                    "username": username,
                    "email": email,
                    "groups": sorted(groups),
                    "onboardingRequired": "onboarding_required" in groups or "onboarding-required" in groups,
                    "accountUrl": keycloak_account_url(),
                    "redirect": home_url(),
                })
                return
            self.send_error(HTTPStatus.NOT_FOUND)
        except Exception as error:
            self.handle_error(error)

    def do_POST(self) -> None:
        try:
            self.require_trusted_proxy()
            if self.path == "/api/invites/signup":
                if not SELF_SERVICE_ENABLED:
                    self.send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "self-service onboarding is disabled"})
                    return
                form = self.read_form()
                code = form.get("code", "")
                username = require_valid_username(form.get("username", ""))
                email = form.get("email", "")
                if "@" not in email or len(email) > 254:
                    raise ValueError("email is invalid")
                invite = find_invite(code)
                if invite is None:
                    raise ValueError("invite code is invalid")
                assert_invite_available(invite, email)
                user_id, temp_password, groups, required_actions = create_keycloak_user(username, email, invite)
                mark_invite_used(invite)
                if self.headers.get("Accept", "").lower().find("application/json") >= 0:
                    self.send_json(HTTPStatus.CREATED, {
                        "ok": True,
                        "userId": user_id,
                        "username": username,
                        "email": email,
                        "groups": groups,
                        "requiredActions": required_actions,
                        "temporaryPassword": temp_password,
                        "accountUrl": keycloak_account_url(),
                    })
                else:
                    self.send_html(render_signup_result(username, email, temp_password, groups, required_actions))
                return
        except Exception as error:
            self.handle_error(error)
            return

        self.send_json(HTTPStatus.GONE, {
            "ok": False,
            "error": "password and MFA enrollment are handled by Keycloak required actions",
            "accountUrl": keycloak_account_url(),
        })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"[onboarding] listening on :{port}", flush=True)
    server.serve_forever()
