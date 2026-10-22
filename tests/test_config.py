from pathlib import Path
import tempfile
import unittest

from autoreviewer.config import ConfigError, load_config


BASE_CONFIG = '''version = 1
[providers.test]
base_url = "https://api.example.test/v1"
api_key_env = "MODEL_TEST_KEY"
[[models]]
id = "reviewer"
provider = "test"
model = "organization/model-name:free"
'''


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "config.toml"

    def load(self, content=BASE_CONFIG):
        self.path.write_text(content, encoding="utf-8")
        return load_config(self.path)

    def test_defaults_and_custom_agent_are_resolved(self):
        config = self.load(BASE_CONFIG + '\n[agents.custom]\ncommand = ["python3", "review.py"]\nargs = ["{model}"]\n')
        self.assertEqual(config.models[0].model, "organization/model-name:free")
        self.assertEqual(config.models[0].agent, "opencode")
        self.assertEqual(config.scan.concurrency, 3)
        self.assertEqual(config.agents["custom"].command, ("python3", "review.py"))

    def test_inline_secrets_and_unknown_options_are_rejected(self):
        for insertion in ('api_key = "secret"', 'apikey = "secret"', 'baseurl = "https://example.test"'):
            with self.subTest(insertion=insertion), self.assertRaises(ConfigError):
                self.load(BASE_CONFIG.replace("[[models]]", insertion + "\n[[models]]"))

    def test_endpoint_auth_and_unsafe_urls_are_rejected(self):
        for url in ("http://api.example.test/v1", "https://user:secret@api.example.test/v1",
                    "https://api.example.test/v1?api_key=secret", "https://api.example.test/v1#secret",
                    "file:///etc/passwd", "https:///missing-host", "https://example.test:99999/v1"):
            with self.subTest(url=url), self.assertRaises(ConfigError):
                self.load(BASE_CONFIG.replace("https://api.example.test/v1", url))

    def test_loopback_http_and_trailing_slash(self):
        for url in ("http://localhost:11434/v1/", "http://127.0.0.1:8000/v1/", "http://[::1]:8000/v1/"):
            with self.subTest(url=url):
                config = self.load(BASE_CONFIG.replace("https://api.example.test/v1", url))
                self.assertEqual(config.providers["test"].base_url, url.rstrip("/"))

    def test_invalid_model_provider_agent_and_collisions(self):
        changes = [
            BASE_CONFIG.replace('provider = "test"', 'provider = "missing"'),
            BASE_CONFIG + 'agent = "missing"\n',
            BASE_CONFIG.replace('id = "reviewer"', 'id = "../escape"'),
            BASE_CONFIG.replace('model = "organization/model-name:free"', 'model = "--unsafe"'),
            BASE_CONFIG + '\n[[models]]\nid = "reviewer"\nprovider = "test"\nmodel = "other"\n',
            BASE_CONFIG.replace('version = 1', 'version = true'),
        ]
        for content in changes:
            with self.subTest(content=content), self.assertRaises(ConfigError):
                self.load(content)

    def test_api_format_wrong_types_are_config_errors(self):
        for value in ('[]', '{}', 'false', '12', '"invalid"'):
            with self.subTest(value=value), self.assertRaises(ConfigError):
                self.load(BASE_CONFIG.replace("[[models]]", f"api_format = {value}\n[[models]]"))

    def test_api_key_env_cannot_overwrite_runtime_or_github_credentials(self):
        names = ("PATH", "HOME", "https_proxy", "TMPDIR", "CODEX_HOME", "XDG_CONFIG_HOME",
                 "GIT_CONFIG_COUNT", "NODE_OPTIONS", "PYTHONHOME", "GITHUB_TOKEN", "GH_TOKEN",
                 "AUTOREVIEWER_AUDIT_PROMPT")
        for name in names:
            with self.subTest(name=name), self.assertRaises(ConfigError):
                self.load(BASE_CONFIG.replace("MODEL_TEST_KEY", name))
        with self.assertRaisesRegex(ConfigError, "different environment variables"):
            self.load(BASE_CONFIG + '\n[github]\nrepository = "owner/repo"\ntoken_env = "MODEL_TEST_KEY"\n')

    def test_separate_github_token_and_model_key_allowed(self):
        config = self.load(BASE_CONFIG + '\n[github]\nrepository = "owner/repo"\ntoken_env = "ISSUES_TOKEN"\nlabels = ["security"]\n')
        self.assertEqual(config.github.token_env, "ISSUES_TOKEN")
        self.assertEqual(config.github.labels, ("security",))

    def test_bounds_and_types_on_scan_limits(self):
        for field, value in (("concurrency", "0"), ("concurrency", "33"), ("concurrency", "true"),
                             ("timeout_seconds", "0"), ("max_output_bytes", "1"), ("excludes", '"*.txt"')):
            with self.subTest(field=field, value=value), self.assertRaises(ConfigError):
                self.load(BASE_CONFIG + f"\n[scan]\n{field} = {value}\n")

    def test_invalid_toml_and_oversized_configuration(self):
        for content in ("not valid TOML", "#" * (1024 * 1024 + 1)):
            with self.subTest(length=len(content)), self.assertRaises(ConfigError):
                self.load(content)


if __name__ == "__main__":
    unittest.main()
