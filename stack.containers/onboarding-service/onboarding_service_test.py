import importlib.util
import os
import tempfile
import unittest
from email.message import Message
from pathlib import Path


def load_service_module():
    os.environ.setdefault("DOMAIN", "example.test")
    os.environ.setdefault("ONBOARDING_TRUSTED_PROXY_SECRET", "proxy-secret")
    os.environ.setdefault("KEYCLOAK_REALM", "webservices")
    os.environ.setdefault("ONBOARDING_INVITES_JSON", "[]")

    module_path = Path(__file__).with_name("onboarding_service.py")
    spec = importlib.util.spec_from_file_location("onboarding_service_under_test", module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


service = load_service_module()


def handler_with_headers(**headers):
    message = Message()
    for name, value in headers.items():
        message[name.replace("_", "-")] = value
    handler = service.Handler.__new__(service.Handler)
    handler.headers = message
    return handler


class OnboardingTrustedProxyTest(unittest.TestCase):
    def test_proxy_secret_is_required(self):
        handler = handler_with_headers(X_Trusted_Proxy_Secret="wrong")

        with self.assertRaises(service.ProxyAuthError):
            handler.require_trusted_proxy()

    def test_proxy_secret_accepts_configured_value(self):
        handler = handler_with_headers(X_Trusted_Proxy_Secret="proxy-secret")

        handler.require_trusted_proxy()

    def test_current_user_ignores_legacy_remote_user_header(self):
        handler = handler_with_headers(Remote_User="spoofed")

        with self.assertRaises(ValueError):
            handler.current_user()

    def test_current_user_accepts_proxy_set_x_remote_user(self):
        handler = handler_with_headers(X_Remote_User="gerald")

        self.assertEqual("gerald", handler.current_user())

    def test_status_groups_detect_keycloak_onboarding_marker(self):
        groups = service.split_groups("users,onboarding_required")

        self.assertIn("onboarding_required", groups)

    def test_keycloak_account_url_uses_realm(self):
        self.assertEqual(
            "https://keycloak.example.test/realms/webservices/account/",
            service.keycloak_account_url(),
        )

    def test_required_actions_resolve_from_modular_method_names(self):
        self.assertEqual(
            ["UPDATE_PASSWORD", "CONFIGURE_TOTP"],
            service.required_actions_for_methods(["password", "totp"]),
        )

        with self.assertRaises(ValueError):
            service.required_actions_for_methods(["wallet"])

    def test_invite_code_can_be_plain_or_hashed(self):
        plain = {"code": "abc123"}
        hashed = {
            "codeHash": "6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090"
        }

        self.assertTrue(service.invite_code_matches(plain, "abc123"))
        self.assertTrue(service.invite_code_matches(hashed, "abc123"))
        self.assertFalse(service.invite_code_matches(hashed, "wrong"))

    def test_invite_policy_enforces_email_domain_and_max_uses(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_state_path = service.STATE_PATH
            service.STATE_PATH = Path(temp_dir) / "state.json"
            try:
                invite = {"id": "team", "emailDomains": ["example.test"], "maxUses": 1}
                service.assert_invite_available(invite, "alice@example.test")
                service.mark_invite_used(invite)

                with self.assertRaises(ValueError):
                    service.assert_invite_available(invite, "bob@example.test")

                with self.assertRaises(ValueError):
                    service.assert_invite_available({"emailDomains": ["example.test"]}, "alice@other.test")
            finally:
                service.STATE_PATH = original_state_path


if __name__ == "__main__":
    unittest.main()
