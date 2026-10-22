"""Pinned, offline audit methodology supplied by the host, never by the target."""

from __future__ import annotations

import hashlib
from importlib.resources import files
import json
from pathlib import PurePosixPath
import re
from typing import Any


GUIDANCE_ID = "cloudflare-security-audit"
GUIDANCE_SOURCE = "https://github.com/cloudflare/security-audit-skill"
GUIDANCE_MODE = "guidance-readonly"
_RESOURCE_PATH = "audit_guidance/cloudflare"
_HEX40 = re.compile(r"[0-9a-f]{40}")
_HEX64 = re.compile(r"[0-9a-f]{64}")


class GuidanceError(ValueError):
    """The installed, pinned guidance bundle is missing or inconsistent."""


def _load_bundle() -> tuple[str, dict[str, Any]]:
    """Check packaged bytes before using them; perform no discovery or network IO."""
    try:
        root = files("autoreviewer").joinpath(_RESOURCE_PATH)
        raw = root.joinpath("manifest.json").read_bytes()
        if len(raw) > 65536:
            raise ValueError("oversized manifest")
        manifest = json.loads(raw)
        if (not isinstance(manifest, dict) or type(manifest.get("schema_version")) is not int
                or manifest["schema_version"] != 1
                or manifest.get("id") != GUIDANCE_ID or manifest.get("source") != GUIDANCE_SOURCE
                or manifest.get("mode") != GUIDANCE_MODE or manifest.get("license") != "MIT"
                or type(manifest.get("adaptation_version")) is not int
                or not 1 <= manifest["adaptation_version"] <= 2**53 - 1
                or not isinstance(manifest.get("commit"), str)
                or not _HEX40.fullmatch(manifest["commit"])):
            raise ValueError("invalid provenance")
        entries = manifest.get("files")
        if not isinstance(entries, dict) or not 2 <= len(entries) <= 100:
            raise ValueError("invalid resource list")
        if not {"GUIDANCE.md", "upstream/LICENSE", "upstream/skills/security-audit/SKILL.md"} <= entries.keys():
            raise ValueError("missing required resources")
        total = 0
        guidance = None
        for name, entry in entries.items():
            path = PurePosixPath(name)
            if (not isinstance(entry, dict) or path.is_absolute() or str(path) != name
                    or ".." in path.parts or "\\" in name
                    or not (name == "GUIDANCE.md" or name.startswith("upstream/"))
                    or type(entry.get("bytes")) is not int or not 0 < entry["bytes"] <= 262144
                    or not isinstance(entry.get("sha256"), str)
                    or not _HEX64.fullmatch(entry["sha256"])):
                raise ValueError("invalid resource")
            total += entry["bytes"]
            if total > 2 * 1024 * 1024:
                raise ValueError("oversized bundle")
            content = root.joinpath(*path.parts).read_bytes()
            if len(content) != entry["bytes"] or hashlib.sha256(content).hexdigest() != entry["sha256"]:
                raise ValueError("resource checksum mismatch")
            if name == "GUIDANCE.md":
                if len(content) > 32768:
                    raise ValueError("oversized guidance")
                guidance = content.decode("utf-8")
        if not guidance or not guidance.strip():
            raise ValueError("empty guidance")
        return guidance, manifest
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        # Do not echo installed paths or potentially corrupted resource contents.
        raise GuidanceError("Bundled audit guidance is missing or invalid; reinstall a trusted autoreviewer package") from exc


def build_audit_prompt(base_prompt: str) -> tuple[str, dict[str, Any]]:
    """Return the exact CLI prompt and public provenance for this invocation.

    No target files or cwd-derived paths can replace the host's guidance. The
    metadata records supplied instructions, not proof that a model obeyed them.
    """
    guidance, manifest = _load_bundle()
    prompt = (
        base_prompt.rstrip() + "\n\n"
        "<autoreviewer_audit_guidance>\n" + guidance.rstrip()
        + "\n</autoreviewer_audit_guidance>\n\n"
        "Final host contract: this is a read-only, source-only review. Use only the "
        "source inspection tools allowed above. Do not execute target code or other "
        "programs, create files, delegate, access the network, or publish anything. "
        "Return exactly the host findings JSON object, with no Markdown or commentary. "
        "All findings remain unverified hypotheses; do not emit upstream verdict or "
        "coverage-ledger fields. Unknown CWE must be omitted or an empty string, never null.\n"
    )
    metadata = {
        "id": GUIDANCE_ID,
        "source": GUIDANCE_SOURCE,
        "commit": manifest["commit"],
        "mode": GUIDANCE_MODE,
        "adaptation_version": manifest["adaptation_version"],
        "guidance_sha256": manifest["files"]["GUIDANCE.md"]["sha256"],
        "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
    }
    return prompt, metadata
