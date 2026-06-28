#!/usr/bin/env python3
import hmac
import html
import json
import os
import re
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

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


def render_page(username: str, groups: set[str], email: str | None) -> str:
    onboarding_required = "onboarding_required" in groups or "onboarding-required" in groups
    heading = "Finish account setup in Keycloak" if onboarding_required else "Account setup complete"
    status = (
        "Keycloak required actions are pending for this account."
        if onboarding_required else
        "This account has no Keycloak required-action marker. Access is admin-managed; continue to the stack."
    )
    action_section = (
        "<section class=\"card\">"
        "<h2>Required actions</h2>"
        "<ol>"
        "<li>Update the temporary password in Keycloak.</li>"
        "<li>Enroll OTP/MFA from the Keycloak account console.</li>"
        "<li>Return to the stack after Keycloak clears required actions.</li>"
        "</ol>"
        f"<a class=\"button\" href=\"{html.escape(keycloak_account_url())}\">Open Keycloak account console</a>"
        f"<a class=\"button\" href=\"{html.escape(home_url())}\">Return to homepage</a>"
        "</section>"
        if onboarding_required else
        "<section class=\"card\">"
        "<h2>Membership</h2>"
        "<p>New membership is created by an administrator in Keycloak. This page does not create accounts.</p>"
        f"<a class=\"button\" href=\"{html.escape(home_url())}\">Return to homepage</a>"
        "</section>"
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
    <h1>{html.escape(heading)}</h1>
    <p>{html.escape(status)}</p>
    <section class="card">
      <p><strong>User:</strong> <code>{html.escape(username)}</code></p>
      <p><strong>Email:</strong> <code>{html.escape(email or "unknown")}</code></p>
      <p><strong>Groups:</strong> <code>{html.escape(group_list)}</code></p>
    </section>
    {action_section}
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

    def send_redirect(self, location: str) -> None:
        self.send_response(HTTPStatus.FOUND)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

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
                self.send_redirect("/")
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
        except Exception as error:
            self.handle_error(error)
            return

        self.send_json(HTTPStatus.GONE, {
            "ok": False,
            "error": "account creation is admin managed; password and MFA enrollment are handled by Keycloak required actions",
            "accountUrl": keycloak_account_url(),
        })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"[onboarding] listening on :{port}", flush=True)
    server.serve_forever()
