"""
Canon adapter for FINOS AI Governance Framework.
Source: github.com/finos/ai-governance-framework

Fetched as ONE repository archive (~1 MB) instead of dozens of GitHub API calls,
so it works without a token and cannot hit the API rate limit.
Risks live in docs/_risks/ri-<n>_<slug>.md (Jekyll collection, YAML front matter).
"""
from __future__ import annotations

import re
from typing import Any

import httpx

from canon.models import SourceState
from canon.sources.base import BaseSourceAdapter
from canon.sources.github_fetch import content_hash, download_archive, read_zip_text

_REPO = "finos/ai-governance-framework"
_RISKS_PATH = "docs/_risks/"

# FINOS front-matter `type:` values
_TYPE_CATEGORY = {"SEC": "security", "OP": "operational", "RC": "regulatory-compliance"}


class FINOSAdapter(BaseSourceAdapter):
    source_id = "finos-aigf"
    source_name = "FINOS AI Governance Framework"
    source_url = f"https://github.com/{_REPO}"

    async def fetch_state(self, client: httpx.AsyncClient) -> SourceState:
        commit_sha, zf = await download_archive(client, _REPO)

        rules: dict[str, Any] = {}
        for info in sorted(zf.infolist(), key=lambda i: i.filename):
            if info.is_dir():
                continue
            # strip the archive's top-level "<repo>-<branch>/" directory
            path = info.filename.split("/", 1)[1] if "/" in info.filename else info.filename
            if not (path.startswith(_RISKS_PATH) and path.endswith(".md")):
                continue
            if "/" in path[len(_RISKS_PATH):]:
                continue  # direct children of docs/_risks/ only
            rule_id, rule = self._parse_risk_markdown(path, read_zip_text(zf, info))
            if rule_id and rule is not None:
                rules[rule_id] = rule

        state = SourceState(
            source_id=self.source_id,
            source_name=self.source_name,
            source_url=self.source_url,
            commit_sha=commit_sha,
            rules=rules,
            fetch_method="github-archive",
        )
        state.compute_hash()
        return state

    def _parse_risk_markdown(
        self, path: str, content: str
    ) -> tuple[str | None, dict[str, Any] | None]:
        content = content.replace("\r\n", "\n")
        filename = path.rsplit("/", 1)[-1][: -len(".md")]

        # Stable id from the "ri-<n>" prefix, so renaming the slug does not look
        # like a removed rule plus an added rule.
        id_match = re.match(r"(ri-\d+)", filename, re.IGNORECASE)
        rule_id = f"FINOS-{(id_match.group(1) if id_match else filename).upper()}"

        fm_match = re.match(r"\A---\s*\n(.*?)\n---\s*\n?(.*)\Z", content, re.DOTALL)
        front, body = (fm_match.group(1), fm_match.group(2)) if fm_match else ("", content)

        def field(name: str) -> str | None:
            m = re.search(rf"^{name}:\s*(.+?)\s*$", front, re.MULTILINE)
            return m.group(1).strip("\"'") if m else None

        title = field("title")
        if not title:
            h = re.search(r"^#{1,2}\s+(.+)$", body, re.MULTILINE)
            title = h.group(1).strip() if h else filename

        rtype = (field("type") or "").upper()
        return rule_id, self.normalise_rules({
            "title": title,
            "description": self._summary(body)[:500],
            # FINOS publishes no severity; do not invent one.
            "severity": "warning",
            "category": _TYPE_CATEGORY.get(rtype, rtype.lower() or "general"),
            "doc_status": field("doc-status") or "",
            "source_path": path,
            "content_hash": content_hash(content),
        })

    @staticmethod
    def _summary(body: str) -> str:
        """First paragraph under '## Summary'; else the first prose paragraph."""
        m = re.search(r"^##\s+Summary\s*\n+(.+?)(?:\n\s*\n|\Z)", body, re.DOTALL | re.MULTILINE)
        if m:
            return " ".join(m.group(1).split())
        for para in re.split(r"\n\s*\n", body):
            para = para.strip()
            if para and not para.startswith(("#", "{%", "<")):
                return " ".join(para.split())
        return ""

    def normalise_rules(self, raw: Any) -> dict[str, Any]:
        return {
            "title": raw.get("title", ""),
            "description": raw.get("description", ""),
            "severity": raw.get("severity", "warning"),
            "category": raw.get("category", "general"),
            "regulatory_refs": ["FINOS-AIGF"],
            "version": "latest",
            "doc_status": raw.get("doc_status", ""),
            "source_path": raw.get("source_path", ""),
            "content_hash": raw.get("content_hash", ""),
        }
