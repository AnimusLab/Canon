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

_GITHUB_API = "https://api.github.com"
_REPO = "OWASP/www-project-top-10-for-large-language-model-applications"
_VULNS_PATHS = ["2_0_vulns", "1_1_vulns"]

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

        vuln_files = []
        for path_prefix in _VULNS_PATHS:
            candidates = [
                f for f in tree
                if f["path"].startswith(path_prefix)
                and f["path"].endswith(".md")
                and "/translations/" not in f["path"]
                and f["type"] == "blob"
                and re.search(r"LLM\d+", f["path"], re.IGNORECASE)
            ]
            if candidates:
                vuln_files = candidates
                break

        rules: dict[str, Any] = {}
        for file_entry in vuln_files:
            content = await self._fetch_raw(client, _REPO, commit_sha, file_entry["path"])
            rule_id, rule = self._parse_vuln_markdown(file_entry["path"], content)
            if rule_id:
                rules[rule_id] = rule

        version_tag = await self._detect_version(client, _REPO, commit_sha, tree)

        state = SourceState(
            source_id=self.source_id,
            source_name=self.source_name,
            source_url=self.source_url,
            commit_sha=commit_sha,
            version_tag=version_tag,
            rules=rules,
        )
        state.compute_hash()
        return state

    async def _fetch_raw(
        self, client: httpx.AsyncClient, repo: str, sha: str, path: str
    ) -> str:
        url = f"https://raw.githubusercontent.com/{repo}/{sha}/{path}"
        resp = await client.get(url, timeout=30)
        resp.raise_for_status()
        return resp.text

    async def _detect_version(
        self, client: httpx.AsyncClient, repo: str, sha: str, tree: list[dict]
    ) -> str | None:
        changelog = next(
            (f for f in tree if f["path"].lower() in ("changelog.md", "changes.md")),
            None,
        )
        if not changelog:
            return None
        content = await self._fetch_raw(client, repo, sha, changelog["path"])
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

        lines = content.split("\n")
        desc_lines = []
        in_desc = False
        for line in lines:
            if line.startswith("#"):
                if in_desc:
                    break
                in_desc = True
                continue
            if in_desc and line.strip():
                desc_lines.append(line.strip())
                if len(" ".join(desc_lines)) > 400:
                    break

        description = " ".join(desc_lines)[:500]
        severity = _OWASP_SEVERITY.get(owasp_id, "warning")

        return rule_id, self.normalise_rules({
            "title": title,
            "description": description,
            "severity": severity,
            "category": "llm-security",
            "owasp_id": owasp_id,
            "source_path": path,
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
        }