import importlib.util
import os
import unittest
from email.message import Message
from pathlib import Path


def load_service_module():
    os.environ.setdefault("DOMAIN", "example.test")
    os.environ.setdefault("ONBOARDING_TRUSTED_PROXY_SECRET", "proxy-secret")
    os.environ.setdefault("KEYCLOAK_REALM", "webservices")

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

    def test_render_page_explains_required_actions_for_existing_users(self):
        page = service.render_page("gerald", {"users", "onboarding_required"}, "gerald@example.test")

        self.assertIn("Finish account setup in Keycloak", page)
        self.assertIn("Update the temporary password in Keycloak.", page)

    def test_render_page_does_not_show_required_actions_without_marker(self):
        page = service.render_page("gerald", {"users"}, "gerald@example.test")

        self.assertIn("Account setup complete", page)
        self.assertNotIn("Update the temporary password in Keycloak.", page)
        self.assertIn("does not create accounts", page)


if __name__ == "__main__":
    unittest.main()
