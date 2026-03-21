"""Tests for kv provider registry — auth injection and URL building."""

import unittest

from kv.providers import (
    get_provider, list_providers, build_auth, build_url, PROVIDERS,
)


class TestProviderRegistry(unittest.TestCase):

    def test_all_providers_exist(self):
        for name in ["openai", "anthropic", "google", "github", "google-cloud"]:
            self.assertIsNotNone(get_provider(name), f"missing provider: {name}")

    def test_unknown_provider_returns_none(self):
        self.assertIsNone(get_provider("nonexistent"))

    def test_list_providers(self):
        names = list_providers()
        self.assertIn("openai", names)
        self.assertIn("anthropic", names)
        self.assertIsInstance(names, list)

    def test_all_providers_have_required_fields(self):
        for name, config in PROVIDERS.items():
            self.assertIn("base_url", config, f"{name} missing base_url")
            self.assertIn("secret_name", config, f"{name} missing secret_name")
            self.assertIn("auth_type", config, f"{name} missing auth_type")


class TestBuildAuth(unittest.TestCase):

    def test_bearer_auth(self):
        config = get_provider("openai")
        headers, params = build_auth(config, "sk-test-key")
        self.assertEqual(headers["Authorization"], "Bearer sk-test-key")
        self.assertEqual(params, {})

    def test_x_api_key_auth(self):
        config = get_provider("anthropic")
        headers, params = build_auth(config, "sk-ant-test")
        self.assertEqual(headers["x-api-key"], "sk-ant-test")
        self.assertNotIn("Authorization", headers)
        self.assertEqual(params, {})

    def test_query_param_auth(self):
        config = get_provider("google")
        headers, params = build_auth(config, "AIza-test")
        self.assertNotIn("Authorization", headers)
        self.assertEqual(params, {"key": "AIza-test"})

    def test_default_headers_included(self):
        config = get_provider("openai")
        headers, _ = build_auth(config, "test")
        self.assertEqual(headers["Content-Type"], "application/json")

    def test_anthropic_version_header(self):
        config = get_provider("anthropic")
        headers, _ = build_auth(config, "test")
        self.assertEqual(headers["anthropic-version"], "2023-06-01")

    def test_github_accept_header(self):
        config = get_provider("github")
        headers, _ = build_auth(config, "test")
        self.assertEqual(headers["Accept"], "application/vnd.github+json")

    def test_secret_not_in_wrong_place(self):
        """Bearer auth should NOT put key in query params."""
        config = get_provider("openai")
        _, params = build_auth(config, "sk-secret")
        self.assertNotIn("sk-secret", str(params))

    def test_query_auth_not_in_headers(self):
        """Query auth should NOT put key in Authorization header."""
        config = get_provider("google")
        headers, _ = build_auth(config, "AIza-secret")
        self.assertNotIn("Authorization", headers)
        self.assertNotIn("AIza-secret", str(headers))


class TestBuildUrl(unittest.TestCase):

    def test_simple_path(self):
        config = get_provider("openai")
        url = build_url(config, "/v1/chat/completions")
        self.assertEqual(url, "https://api.openai.com/v1/chat/completions")

    def test_path_without_leading_slash(self):
        config = get_provider("openai")
        url = build_url(config, "v1/models")
        self.assertEqual(url, "https://api.openai.com/v1/models")

    def test_query_params_appended(self):
        config = get_provider("google")
        url = build_url(config, "/v1/models", {"key": "test123"})
        self.assertIn("key=test123", url)
        self.assertIn("?", url)

    def test_base_url_trailing_slash_handled(self):
        config = {"base_url": "https://api.example.com/", "auth_type": "bearer"}
        url = build_url(config, "/v1/test")
        self.assertEqual(url, "https://api.example.com/v1/test")


if __name__ == "__main__":
    unittest.main()
