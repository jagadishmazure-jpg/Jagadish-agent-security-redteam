"""Tool-call policy: allowlist plus argument validation.

Every tool invocation passes through the policy *before* execution:

* the tool must be on the allowlist,
* ``send_email`` may only target approved domains,
* ``read_file`` is confined to the sandbox root (no ``..`` escapes),
* URLs are rejected when they target non-allowlisted tools, attacker
  infrastructure, or cloud metadata endpoints.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str


class ToolCallPolicy:
    """Allowlist + argument validation for agent tool calls."""

    DEFAULT_ALLOWED_TOOLS = ("send_email", "web_search", "read_file")
    BLOCKED_URL_HOSTS = ("evil.example.com", "collector.evil.example.com")
    METADATA_IP = "169.254.169.254"

    def __init__(
        self,
        allowed_tools: tuple[str, ...] | None = None,
        allowed_email_domains: tuple[str, ...] = ("example.com",),
        sandbox_root: str = "/workspace/sandbox",
    ) -> None:
        self.allowed_tools = allowed_tools or self.DEFAULT_ALLOWED_TOOLS
        self.allowed_email_domains = allowed_email_domains
        self.sandbox_root = sandbox_root

    def evaluate(self, tool_name: str, args: dict) -> PolicyDecision:
        """Decide whether ``tool_name(**args)`` may execute."""
        if tool_name not in self.allowed_tools:
            return PolicyDecision(False, f"tool '{tool_name}' is not on the allowlist")

        if tool_name == "send_email":
            return self._check_email(args)
        if tool_name == "read_file":
            return self._check_read_file(args)
        if tool_name == "web_search":
            return self._check_web_search(args)
        return PolicyDecision(True, "allowed")

    # -- per-tool validators -------------------------------------------------
    def _check_email(self, args: dict) -> PolicyDecision:
        to = str(args.get("to", ""))
        domain = to.rsplit("@", 1)[-1].lower() if "@" in to else ""
        if domain not in self.allowed_email_domains:
            return PolicyDecision(False, f"email domain '{domain}' is not allowlisted")
        return PolicyDecision(True, "allowed")

    def _check_read_file(self, args: dict) -> PolicyDecision:
        path = str(args.get("path", ""))
        if ".." in re.split(r"[\\/]", path):
            return PolicyDecision(False, "path traversal detected")
        normalized = os.path.normpath(os.path.join(self.sandbox_root, path.lstrip("/")))
        if not normalized.startswith(os.path.normpath(self.sandbox_root) + os.sep):
            return PolicyDecision(False, f"path '{path}' escapes the sandbox")
        return PolicyDecision(True, "allowed")

    def _check_web_search(self, args: dict) -> PolicyDecision:
        query = str(args.get("query", ""))
        if re.search(r"https?://\S*evil\.example\.com", query):
            return PolicyDecision(False, "query references attacker infrastructure")
        return PolicyDecision(True, "allowed")

    def url_allowed(self, url: str) -> PolicyDecision:
        """Standalone URL check used for defense-in-depth on HTTP-ish tools."""
        host = urlparse(url).hostname or ""
        if host in self.BLOCKED_URL_HOSTS:
            return PolicyDecision(False, f"host '{host}' is blocklisted")
        if host == self.METADATA_IP:
            return PolicyDecision(False, "cloud metadata endpoint is forbidden")
        return PolicyDecision(True, "allowed")
