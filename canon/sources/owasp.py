"""
Canon adapter for OWASP LLM Top 10.
Source: github.com/OWASP/www-project-top-10-for-large-language-model-applications
"""
from __future__ import annotations

import re
from typing import Any
import httpx

from canon.models import SourceState
from canon.sources.base import BaseSourceAdapter
from canon.sources.github_fetch import (
    SourceFetchError,
    content_hash,
    get_head_sha,
    is_rate_limited,
)

_GITHUB_API = "https://api.github.com"
_REPO = "OWASP/www-project-top-10-for-large-language-model-applications"
_VULNS_PATHS = ["2_0_vulns", "1_1_vulns"]

# Used ONLY when the GitHub API is rate-limited: the repo's file list can then not
# be discovered, so the known 2025 (v2.0) entries are fetched directly from
# raw.githubusercontent.com (which is not subject to the API quota). A missing
# file is an error, never a silently dropped rule.
_FALLBACK_DIR = "2_0_vulns"
_FALLBACK_FILES = [
    "LLM00_Preface.md",
    "LLM01_PromptInjection.md",
    "LLM02_SensitiveInformationDisclosure.md",
    "LLM03_SupplyChain.md",
    "LLM04_DataModelPoisoning.md",
    "LLM05_ImproperOutputHandling.md",
    "LLM06_ExcessiveAgency.md",
    "LLM07_SystemPromptLeakage.md",
    "LLM08_VectorAndEmbeddingWeaknesses.md",
    "LLM09_Misinformation.md",
    "LLM10_UnboundedConsumption.md",
]

_OWASP_SEVERITY = {
    "LLM01": "critical",
    "LLM02": "critical",
    "LLM03": "warning",
    "LLM04": "critical",
    "LLM05": "critical",
    "LLM06": "warning",
    "LLM07": "warning",
    "LLM08": "warning",
    "LLM09": "warning",
    "LLM10": "info",
}


class OWASPAdapter(BaseSourceAdapter):
    source_id = "owasp-llm-top10"
    source_name = "OWASP LLM Top 10"
    source_url = f"https://github.com/{_REPO}"

    async def fetch_state(self, client: httpx.AsyncClient) -> SourceState:
        fetch_method = "github-api"
        fetch_note: str | None = None
        try:
            commit_sha, vuln_paths, changelog_path = await self._discover_via_api(client)
        except httpx.HTTPStatusError as exc:
            if not is_rate_limited(exc):
                raise
            # API quota exhausted: use the non-API path (git smart-HTTP + raw).
            commit_sha = await get_head_sha(client, _REPO)
            vuln_paths = [f"{_FALLBACK_DIR}/{name}" for name in _FALLBACK_FILES]
            changelog_path = "changes.md"
            fetch_method = "raw-manifest"
            fetch_note = (
                "GitHub API rate-limited; used bundled OWASP file list. "
                "New OWASP entries are not discovered until the API is available "
                "(set GITHUB_TOKEN)."
            )

        rules: dict[str, Any] = {}
        for path in vuln_paths:
            try:
                content = await self._fetch_raw(client, _REPO, commit_sha, path)
            except httpx.HTTPStatusError as exc:
                if fetch_method == "raw-manifest" and exc.response.status_code == 404:
                    raise SourceFetchError(
                        f"bundled OWASP file list is stale ({path} not found). "
                        "Set GITHUB_TOKEN so Canon can discover files via the API."
                    ) from exc
                raise
            rule_id, rule = self._parse_vuln_markdown(path, content)
            if rule_id:
                rules[rule_id] = rule

        version_tag = await self._detect_version(client, _REPO, commit_sha, changelog_path)

        state = SourceState(
            source_id=self.source_id,
            source_name=self.source_name,
            source_url=self.source_url,
            commit_sha=commit_sha,
            version_tag=version_tag,
            rules=rules,
            fetch_method=fetch_method,
            fetch_note=fetch_note,
        )
        state.compute_hash()
        return state

    async def _discover_via_api(
        self, client: httpx.AsyncClient
    ) -> tuple[str, list[str], str | None]:
        """commit sha, vulnerability file paths, changelog path (REST API: 2 requests)."""
        resp = await client.get(
            f"{_GITHUB_API}/repos/{_REPO}/commits/main",
            headers={"Accept": "application/vnd.github.v3+json"},
            timeout=30,
        )
        resp.raise_for_status()
        commit_sha = resp.json()["sha"]

        tree_resp = await client.get(
            f"{_GITHUB_API}/repos/{_REPO}/git/trees/{commit_sha}?recursive=1",
            headers={"Accept": "application/vnd.github.v3+json"},
            timeout=30,
        )
        tree_resp.raise_for_status()
        tree = tree_resp.json().get("tree", [])

        vuln_paths: list[str] = []
        for path_prefix in _VULNS_PATHS:
            candidates = [
                f["path"] for f in tree
                if f["path"].startswith(path_prefix)
                and f["path"].endswith(".md")
                and "/translations/" not in f["path"]
                and f["type"] == "blob"
                and re.search(r"LLM\d+", f["path"], re.IGNORECASE)
            ]
            if candidates:
                vuln_paths = candidates
                break

        changelog = next(
            (f["path"] for f in tree if f["path"].lower() in ("changelog.md", "changes.md")),
            None,
        )
        return commit_sha, vuln_paths, changelog

    async def _fetch_raw(
        self, client: httpx.AsyncClient, repo: str, sha: str, path: str
    ) -> str:
        url = f"https://raw.githubusercontent.com/{repo}/{sha}/{path}"
        resp = await client.get(url, timeout=30)
        resp.raise_for_status()
        return resp.text

    async def _detect_version(
        self, client: httpx.AsyncClient, repo: str, sha: str, changelog_path: str | None
    ) -> str | None:
        if not changelog_path:
            return None
        try:
            content = await self._fetch_raw(client, repo, sha, changelog_path)
        except httpx.HTTPStatusError:
            return None  # version is informational; never fail the fetch over it
        m = re.search(r"##\s+\[?(\d+\.\d+[\.\d]*)\]?", content)
        return m.group(1) if m else None

    def _parse_vuln_markdown(
        self, path: str, content: str
    ) -> tuple[str | None, dict[str, Any] | None]:
        id_match = re.search(r"(LLM\d+)", path, re.IGNORECASE)
        if not id_match:
            return None, None

        owasp_id = id_match.group(1).upper()
        rule_id = f"OWASP-{owasp_id}"

        title_match = re.search(r"^#{1,2}\s+(.+)$", content, re.MULTILINE)
        title = title_match.group(1).strip() if title_match else owasp_id

        description = self._first_paragraph(content)[:500]
        severity = _OWASP_SEVERITY.get(owasp_id, "warning")

        return rule_id, self.normalise_rules({
            "title": title,
            "description": description,
            "severity": severity,
            "category": "llm-security",
            "owasp_id": owasp_id,
            "source_path": path,
            "content_hash": content_hash(content),
        })

    def normalise_rules(self, raw: Any) -> dict[str, Any]:
        return {
            "title": raw.get("title", ""),
            "description": raw.get("description", ""),
            "severity": raw.get("severity", "warning"),
            "category": raw.get("category", "llm-security"),
            "regulatory_refs": ["OWASP-LLM-TOP10"],
            "version": "2.0",
            "owasp_id": raw.get("owasp_id", ""),
            "source_path": raw.get("source_path", ""),
            "content_hash": raw.get("content_hash", ""),
        }

    @staticmethod
    def _first_paragraph(content: str) -> str:
        """First prose paragraph of the document, skipping headings.
        (OWASP files go '## LLMxx' -> '### Description' -> text, so the old
        stop-at-next-heading logic returned an empty string for every entry.)"""
        collected: list[str] = []
        for line in content.replace("\r\n", "\n").split("\n"):
            text = line.strip()
            if text.startswith("#") or not text:
                if collected:
                    break  # end of the first prose paragraph
                continue   # still skipping headings / blank lines
            collected.append(text)
        return " ".join(collected)