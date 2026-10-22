import json
from pathlib import Path
import tempfile
import tomllib
import unittest
from unittest.mock import patch

from autoreviewer.adapters import AdapterError, LaunchSpec, build_command, extract_output
from autoreviewer.config import AgentConfig, Model, Provider


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.secret = "sample-only-secret"

    def launch(self, adapter, fmt, *, args=(), model="vendor/model", key="sample-only-secret"):
        return build_command(
            Model("test", "provider", model, adapter),
            Provider("provider", "https://provider.example/v1", "TEST_API_KEY", fmt),
            AgentConfig(args=args), self.workspace, self.root / adapter, "Audit this repository.", key,
        )

    def test_opencode_configuration_keeps_secret_out_of_argv_and_config(self):
        spec = self.launch("opencode", "openai-chat")
        self.assertEqual(spec.argv[:4], ["opencode", "run", "--format", "json"])
        self.assertNotIn(self.secret, " ".join(spec.argv))
        config = json.loads(spec.env["OPENCODE_CONFIG_CONTENT"])
        self.assertNotIn(self.secret, spec.env["OPENCODE_CONFIG_CONTENT"])
        self.assertEqual(config["permission"]["*"], "deny")
        self.assertEqual(config["permission"]["read"], "allow")
        self.assertEqual(spec.env["OPENCODE_DISABLE_PROJECT_CONFIG"], "1")
        self.assertEqual(spec.env["AUTOREVIEWER_API_KEY"], self.secret)
        self.assertEqual(config["provider"]["autoreviewer"]["options"]["apiKey"], "{env:AUTOREVIEWER_API_KEY}")

    def test_codex_configuration_isolated_and_response_protocol(self):
        spec = self.launch("codex", "openai-responses")
        config_text = (Path(spec.env["CODEX_HOME"]) / "config.toml").read_text()
        config = tomllib.loads(config_text)
        self.assertEqual(config["sandbox_mode"], "read-only")
        self.assertEqual(config["approval_policy"], "never")
        self.assertEqual(config["model_providers"]["autoreviewer"]["wire_api"], "responses")
        self.assertEqual(config["model_providers"]["autoreviewer"]["env_key"], "AUTOREVIEWER_API_KEY")
        self.assertNotIn(self.secret, config_text)
        self.assertNotIn(self.secret, " ".join(spec.argv))
        self.assertEqual(spec.output_path.parent, self.root / "codex")
        self.assertIn("--ignore-rules", spec.argv)

    def test_claude_is_readonly_and_disables_other_tools(self):
        spec = self.launch("claude", "anthropic")
        self.assertIn("--restricted", spec.argv)
        self.assertIn("--safe-mode", spec.argv)
        self.assertEqual(spec.argv[spec.argv.index("--tools") + 1], "Read,Glob,Grep")
        self.assertIn("--strict-mcp-config", spec.argv)
        self.assertNotIn("--dangerously-skip-permissions", spec.argv)
        self.assertEqual(spec.env["ANTHROPIC_API_KEY"], self.secret)

    def test_gemini_auth_and_allowed_tools(self):
        spec = self.launch("gemini", "gemini")
        settings = json.loads(Path(spec.env["GEMINI_CLI_SYSTEM_SETTINGS_PATH"]).read_text())
        self.assertEqual(settings["security"]["auth"]["selectedType"], "gemini-api-key")
        self.assertFalse(settings["hooksConfig"]["enabled"])
        self.assertFalse(settings["admin"]["mcp"]["enabled"])
        self.assertNotIn("run_shell_command", settings["tools"]["core"])
        self.assertFalse(settings["general"]["plan"]["modelRouting"])
        self.assertEqual(spec.env["GEMINI_API_KEY"], self.secret)

    def test_mismatched_protocols_fail_before_creating_config(self):
        for adapter in ("codex", "claude", "gemini"):
            with self.subTest(adapter=adapter), self.assertRaisesRegex(AdapterError, "requires api_format"):
                self.launch(adapter, "openai-chat")
            self.assertFalse((self.root / adapter).exists())

    def test_model_cannot_be_an_option(self):
        with self.assertRaisesRegex(AdapterError, "not a CLI option"):
            self.launch("codex", "openai-responses", model="--dangerously-bypass-approvals-and-sandbox")

    def test_builtin_extra_args_require_custom_contract(self):
        with self.assertRaises(AdapterError):
            self.launch("opencode", "openai-chat", args=("--share",))

    def test_custom_templates_are_single_arguments_and_key_only_environment(self):
        spec = build_command(
            Model("m", "p", "model; echo nope", "custom"),
            Provider("p", "https://example.test/v1"),
            AgentConfig(("my-agent",), ("--model={model}", "{prompt}", "--out", "{output_file}")),
            self.workspace, self.root / "state", "Prompt $HOME `id`", self.secret,
        )
        self.assertEqual(spec.argv[1], "--model=model; echo nope")
        self.assertEqual(spec.argv[2], "Prompt $HOME `id`")
        self.assertEqual(spec.output_format, "file")
        self.assertNotIn(self.secret, " ".join(spec.argv))
        self.assertEqual(spec.env["AUTOREVIEWER_API_KEY"], self.secret)

    def test_custom_templates_reject_unknown_attributes_and_secret_fields(self):
        for template in ("{api_key}", "{model.__class__}", "{model!r}", "{model:10}", "{"):
            with self.subTest(template=template), self.assertRaises(AdapterError):
                build_command(
                    Model("m", "p", "model", "custom"), Provider("p", "https://example.test"),
                    AgentConfig(("agent",), (template,)), self.workspace, self.root / "custom", "prompt", None,
                )

    def test_custom_stdout_contract(self):
        spec = build_command(
            Model("m", "p", "model", "custom"), Provider("p", "https://example.test"),
            AgentConfig(("agent",), ("{prompt}",)), self.workspace, self.root / "custom", "prompt", None,
        )
        self.assertIsNone(spec.output_path)
        self.assertEqual(extract_output(spec, '{"findings":[]}'), '{"findings":[]}')

    def test_opencode_extracts_final_text_and_rejects_error_events(self):
        spec = LaunchSpec([], {}, output_format="opencode-jsonl")
        stream = '\n'.join(json.dumps(event) for event in [
            {"type": "step_start"}, {"type": "text", "part": {"text": "Reading files."}},
            {"type": "tool_use"}, {"type": "text", "part": {"text": '{"findings":[]}'}},
        ])
        self.assertEqual(extract_output(spec, stream), '{"findings":[]}')
        with self.assertRaises(AdapterError):
            extract_output(spec, stream + '\n{"type":"error","message":"secret"}')
        for malformed in ('oops', '[1]', '{"type":"text","part":null}', '{"type":"tool_use"}'):
            with self.subTest(output=malformed), self.assertRaises(AdapterError):
                extract_output(spec, malformed)

    def test_opencode_api_errors_classify_http_status_without_provider_secrets(self):
        spec = LaunchSpec([], {}, output_format="opencode-jsonl")
        expected = {
            400: "request rejected",
            401: "authentication failed",
            403: "access denied",
            404: "model or endpoint unavailable",
            429: "rate limit exceeded",
            500: "service error",
            503: "service error",
            599: "service error",
            422: "request failed",
        }
        for status, reason in expected.items():
            event = {
                "type": "error",
                "error": {
                    "name": "APIError",
                    "data": {
                        "statusCode": status,
                        "message": "Function not found for account private-account-id",
                        "responseBody": "raw body with sk-test-secret",
                        "responseHeaders": {"Authorization": "Bearer header-secret"},
                    },
                },
            }
            with self.subTest(status=status), self.assertRaises(AdapterError) as caught:
                extract_output(spec, json.dumps(event))
            self.assertEqual(str(caught.exception), f"OpenCode API error (HTTP {status}): {reason}")
            for secret in ("private-account-id", "sk-test-secret", "header-secret", "Function not found"):
                self.assertNotIn(secret, repr(caught.exception))

    def test_opencode_malformed_api_error_metadata_uses_safe_fallback(self):
        spec = LaunchSpec([], {}, output_format="opencode-jsonl")
        malformed = [None, "private-detail", [], {},
                     {"name": "OtherError", "data": {"statusCode": 404}},
                     {"name": [], "data": {"statusCode": 404}},
                     {"name": "APIError", "data": "private-detail"},
                     {"name": "APIError", "data": []}]
        malformed.extend(
            {"name": "APIError", "data": {"statusCode": value}}
            for value in (None, True, False, "404", 404.0, [], {}, 99, 600)
        )
        for error in malformed:
            with self.subTest(error=error), self.assertRaises(AdapterError) as caught:
                extract_output(spec, json.dumps({"type": "error", "error": error}))
            self.assertEqual(str(caught.exception), "OpenCode reported an error")

    def test_native_envelopes_and_errors(self):
        for fmt, key in (("claude-json", "result"), ("gemini-json", "response")):
            spec = LaunchSpec([], {}, output_format=fmt)
            with self.subTest(fmt=fmt):
                self.assertEqual(extract_output(spec, json.dumps({key: '{"findings":[]}'})), '{"findings":[]}')
                for payload in ({key: "answer", "error": {"message": "secret"}}, {key: "answer", "is_error": True}, {}, [], {key: []}):
                    with self.assertRaises(AdapterError):
                        extract_output(spec, json.dumps(payload))

    def test_output_file_missing_symlink_non_utf8_and_size_limits(self):
        path = self.root / "result.json"
        spec = LaunchSpec([], {}, path, "file")
        with self.assertRaises(AdapterError):
            extract_output(spec, "")
        target = self.root / "target.json"
        target.write_text('{"findings":[]}')
        path.symlink_to(target)
        with self.assertRaises(AdapterError):
            extract_output(spec, "")
        path.unlink()
        path.write_bytes(b"\xff")
        with self.assertRaises(AdapterError):
            extract_output(spec, "")
        path.write_text('{"findings":[]}')
        self.assertEqual(extract_output(spec, "ignored"), '{"findings":[]}')
        with patch("autoreviewer.adapters.MAX_OUTPUT_BYTES", 3), self.assertRaises(AdapterError):
            extract_output(spec, "")


if __name__ == "__main__":
    unittest.main()
