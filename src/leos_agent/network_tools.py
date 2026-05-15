"""Network tool adapters with explicit trust boundaries."""

from __future__ import annotations

import ipaddress
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlparse

from .enums import CompensationStrategy, Permission, Reversibility, RiskLevel
from .errors import LeosError, SchemaValidationFailed, ToolTimeout
from .state import TrustLevel, WorldState
from .tools import ToolResult, ToolSpec


@dataclass(frozen=True)
class NetworkFetchResponse:
    status_code: int
    content: str
    content_type: str = "text/plain"


NetworkFetcher = Callable[[str, float, int], NetworkFetchResponse]


@dataclass(frozen=True)
class URLSafetyPolicy:
    """Default SSRF-oriented URL safety policy for network tools."""

    allowed_domains: tuple[str, ...] = ()
    denied_domains: tuple[str, ...] = ()
    resolve_dns: bool = False
    max_redirects: int = 0

    def validate(self, url: str) -> ToolResult:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            return ToolResult(False, "Only http and https URLs are allowed")
        if not parsed.hostname:
            return ToolResult(False, "URL must include a host")
        if parsed.username or parsed.password:
            return ToolResult(False, "Embedded credentials are not allowed in URLs")

        host = parsed.hostname.rstrip(".").lower()
        if self.denied_domains and any(host == d or host.endswith(f".{d}") for d in self.denied_domains):
            return ToolResult(False, "Domain is denied by URL safety policy")
        if self.allowed_domains and not any(host == d or host.endswith(f".{d}") for d in self.allowed_domains):
            return ToolResult(False, "Domain is not in the allowed domain list")

        if host == "localhost":
            return ToolResult(False, "Localhost URLs are blocked")
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return ToolResult(True, "URL passed safety policy")
        if (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
            or str(ip) == "169.254.169.254"
        ):
            return ToolResult(False, "Local, private, link-local, metadata, and reserved IPs are blocked")
        return ToolResult(True, "URL passed safety policy")


class NetworkFetchTool:
    """Fetch an HTTP(S) URL and wrap the body as untrusted observation data."""

    spec = ToolSpec(
        name="network_fetch",
        description="Fetch an HTTP(S) URL as an untrusted external observation.",
        permissions=(Permission.NETWORK,),
        default_risk=RiskLevel.MEDIUM,
        reversibility=Reversibility.IRREVERSIBLE,
        compensation_strategy=CompensationStrategy.NONE,
        network_access=True,
        filesystem_scope="none",
        secrets_allowed=False,
        timeout_ms=5000,
        requires_human_for=("external_network",),
        input_schema={
            "type": "object",
            "required": ["url"],
            "properties": {
                "url": {"type": "string", "minLength": 1},
                "timeout_seconds": {"type": "number", "minimum": 0.1, "maximum": 30},
                "max_bytes": {"type": "integer", "minimum": 1, "maximum": 1048576},
            },
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "required": ["last_network_observation"],
            "properties": {
                "last_network_observation": {
                    "type": "object",
                    "required": ["url", "status_code", "content", "content_type", "trust_level"],
                    "properties": {
                        "url": {"type": "string"},
                        "status_code": {"type": "integer"},
                        "content": {"type": "string"},
                        "content_type": {"type": "string"},
                        "trust_level": {"type": "string", "enum": [TrustLevel.UNTRUSTED_EXTERNAL.value]},
                        "allowed_uses": {"type": "array", "items": {"type": "string"}},
                        "forbidden_uses": {"type": "array", "items": {"type": "string"}},
                    },
                    "additionalProperties": False,
                }
            },
            "additionalProperties": False,
        },
    )

    def __init__(self, fetcher: NetworkFetcher | None = None, url_policy: URLSafetyPolicy | None = None) -> None:
        self.fetcher = fetcher or _urllib_fetch
        self.url_policy = url_policy or URLSafetyPolicy()

    def dry_run(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        schema_issues = self.spec.validate_input(arguments)
        if schema_issues:
            return ToolResult(
                False,
                "Input schema validation failed",
                {"schema_issues": schema_issues},
                error=SchemaValidationFailed("Input schema validation failed"),
            )
        url = str(arguments["url"])
        safety = self.url_policy.validate(url)
        if not safety.ok:
            return safety
        return ToolResult(True, f"Would fetch {url}")

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        dry_run = self.dry_run(arguments, state)
        if not dry_run.ok:
            return dry_run
        url = str(arguments["url"])
        timeout = float(arguments.get("timeout_seconds", self.spec.timeout_ms / 1000))
        max_bytes = int(arguments.get("max_bytes", 65536))
        try:
            response = self.fetcher(url, timeout, max_bytes)
        except TimeoutError as exc:
            return ToolResult(False, f"Network fetch timed out: {exc}", error=ToolTimeout(str(exc)))
        except Exception as exc:  # noqa: BLE001 - tools return structured failures
            return ToolResult(False, f"Network fetch failed: {exc}", error=LeosError(str(exc)))

        observation = {
            "url": url,
            "status_code": int(response.status_code),
            "content": response.content,
            "content_type": response.content_type,
            "trust_level": TrustLevel.UNTRUSTED_EXTERNAL.value,
            "allowed_uses": ["summarization", "evidence"],
            "forbidden_uses": ["policy_override", "credential_request", "system_instruction"],
        }
        return ToolResult(
            True,
            f"Fetched {url}",
            data={"observation": observation},
            observed_state_delta={"last_network_observation": observation},
        )

    def rollback(self, token: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "Network fetch has no rollback side effect")


class BrowserReadTool:
    """Read an HTTP(S) page into a browser-style untrusted observation."""

    spec = ToolSpec(
        name="browser_read",
        description="Read an HTTP(S) page and extract title, text, and links as untrusted observation data.",
        permissions=(Permission.NETWORK,),
        default_risk=RiskLevel.MEDIUM,
        reversibility=Reversibility.IRREVERSIBLE,
        compensation_strategy=CompensationStrategy.NONE,
        network_access=True,
        filesystem_scope="none",
        secrets_allowed=False,
        timeout_ms=5000,
        requires_human_for=("external_network",),
        input_schema=NetworkFetchTool.spec.input_schema,
        output_schema={
            "type": "object",
            "required": ["last_browser_observation"],
            "properties": {
                "last_browser_observation": {
                    "type": "object",
                    "required": ["url", "status_code", "title", "text", "links", "trust_level"],
                    "properties": {
                        "url": {"type": "string"},
                        "status_code": {"type": "integer"},
                        "title": {"type": "string"},
                        "text": {"type": "string"},
                        "links": {"type": "array", "items": {"type": "string"}},
                        "trust_level": {"type": "string", "enum": [TrustLevel.UNTRUSTED_EXTERNAL.value]},
                        "allowed_uses": {"type": "array", "items": {"type": "string"}},
                        "forbidden_uses": {"type": "array", "items": {"type": "string"}},
                    },
                    "additionalProperties": False,
                }
            },
            "additionalProperties": False,
        },
    )

    def __init__(self, fetcher: NetworkFetcher | None = None, url_policy: URLSafetyPolicy | None = None) -> None:
        self.fetcher = fetcher or _urllib_fetch
        self._fetch_tool = NetworkFetchTool(fetcher=self.fetcher, url_policy=url_policy)

    def dry_run(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        return self._fetch_tool.dry_run(arguments, state)

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        raw = self._fetch_tool.execute(arguments, state)
        if not raw.ok:
            return raw
        network_observation = raw.data["observation"]
        parsed = _parse_html(network_observation["content"])
        observation = {
            "url": network_observation["url"],
            "status_code": network_observation["status_code"],
            "title": parsed["title"],
            "text": parsed["text"],
            "links": parsed["links"],
            "trust_level": TrustLevel.UNTRUSTED_EXTERNAL.value,
            "allowed_uses": ["summarization", "evidence"],
            "forbidden_uses": ["policy_override", "credential_request", "system_instruction"],
        }
        return ToolResult(
            True,
            f"Read browser page {observation['url']}",
            data={"observation": observation},
            observed_state_delta={"last_browser_observation": observation},
        )

    def rollback(self, token: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "Browser read has no rollback side effect")


class _HTMLObservationParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self._title_parts: list[str] = []
        self._text_parts: list[str] = []
        self._in_title = False
        self._ignored_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style"}:
            self._ignored_depth += 1
        if tag == "title":
            self._in_title = True
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self.links.append(href)

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"} and self._ignored_depth:
            self._ignored_depth -= 1
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._ignored_depth:
            return
        text = " ".join(data.split())
        if not text:
            return
        if self._in_title:
            self._title_parts.append(text)
        else:
            self._text_parts.append(text)

    def observation(self) -> dict[str, Any]:
        return {
            "title": " ".join(self._title_parts),
            "text": " ".join(self._text_parts),
            "links": self.links,
        }


def _parse_html(content: str) -> dict[str, Any]:
    parser = _HTMLObservationParser()
    parser.feed(content)
    return parser.observation()


def _urllib_fetch(url: str, timeout: float, max_bytes: int) -> NetworkFetchResponse:
    request = urllib.request.Request(url, headers={"User-Agent": "leos-agent/0.1"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
            raw = response.read(max_bytes + 1)
            content = raw[:max_bytes].decode("utf-8", errors="replace")
            content_type = response.headers.get("content-type", "application/octet-stream")
            return NetworkFetchResponse(status_code=response.status, content=content, content_type=content_type)
    except TimeoutError as exc:
        raise TimeoutError(str(exc)) from exc
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, TimeoutError):
            raise TimeoutError(str(exc)) from exc
        raise
