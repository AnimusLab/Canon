"""
Canon adapter for FINOS AI Governance Framework.
Source: github.com/finos/ai-governance-framework
"""
from __future__ import annotations

import base64
import re
from typing import Any
import httpx

from canon.models import SourceState
from canon.sources.base import BaseSourceAdapter

_GITHUB_API = "https://api.github.com"
_REPO = "finos/ai-governance-framework"
_RISKS_PATH = "docs/risks"


class FINOSAdapter(BaseSourceAdapter):
    source_id = "finos-aigf"
    source_name = "FINOS AI Governance Framework"
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

        risk_files = [
            f for f in tree
            if f["path"].startswith(_RISKS_PATH)
            and f["path"].endswith(".md")
            and f["type"] == "blob"
        ]

        rules: dict[str, Any] = {}
        for file_entry in risk_files:
            content = await self._fetch_file(client, file_entry["url"])
            rule_id, rule = self._parse_risk_markdown(file_entry["path"], content)
            if rule_id:
                rules[rule_id] = rule

        state = SourceState(
            source_id=self.source_id,
            source_name=self.source_name,
            source_url=self.source_url,
            commit_sha=commit_sha,
            rules=rules,
        )
        state.compute_hash()
        return state

    async def _fetch_file(self, client: httpx.AsyncClient, blob_url: str) -> str:
        resp = await client.get(
            blob_url,
            headers={"Accept": "application/vnd.github.v3.raw"},
            timeout=30,
        )
        resp.raise_for_status()
        try:
            data = resp.json()
            if isinstance(data, dict) and data.get("encoding") == "base64":
                return base64.b64decode(data["content"]).decode("utf-8")
        except Exception:
            pass
        return resp.text

    def _parse_risk_markdown(
        self, path: str, content: str
    ) -> tuple[str | None, dict[str, Any] | None]:
        filename = path.split("/")[-1].replace(".md", "")
        rule_id = f"FINOS-{filename.upper()}"

        title_match = re.search(r"^#\s+(.+)$", content, re.MULTILINE)
        title = title_match.group(1).strip() if title_match else filename

        desc_match = re.search(r"^#\s+.+\n+(.+?)(?:\n\n|\n#)", content, re.DOTALL)
        description = desc_match.group(1).strip() if desc_match else ""

        severity = "warning"
        sev_match = re.search(
            r"(?:risk.?level|severity)[:\s]+(\w+)", content, re.IGNORECASE
        )
        if sev_match:
            raw = sev_match.group(1).lower()
            if raw in ("high", "critical"):
                severity = "critical"
            elif raw in ("low", "info", "informational"):
                severity = "info"

        cat_match = re.search(
            r"(?:category|domain)[:\s]+(.+)$", content, re.IGNORECASE | re.MULTILINE
        )
        category = cat_match.group(1).strip() if cat_match else "general"

        return rule_id, self.normalise_rules({
            "title": title,
            "description": description[:500],
            "severity": severity,
            "category": category,
            "source_path": path,
        })

    def normalise_rules(self, raw: Any) -> dict[str, Any]:
        return {
            "title": raw.get("title", ""),
            "description": raw.get("description", ""),
            "severity": raw.get("severity", "warning"),
            "category": raw.get("category", "general"),
            "regulatory_refs": ["FINOS-AIGF"],
            "version": "latest",
            "source_path": raw.get("source_path", ""),
        }