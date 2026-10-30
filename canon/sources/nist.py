"""
Canon adapter for NIST AI Risk Management Framework.
Source: csrc.nist.gov CPRT API + hardcoded stable fallback.
"""
from __future__ import annotations

from typing import Any
import httpx

from canon.models import SourceState
from canon.sources.base import BaseSourceAdapter
from canon.sources.github_fetch import describe_error

_NIST_CPRT_URL = "https://csrc.nist.gov/extensions/nudgeapi/public/api/cprt"
_NIST_RMF_ID = "ai_rmf"


class NISTAdapter(BaseSourceAdapter):
    source_id = "nist-ai-rmf"
    source_name = "NIST AI Risk Management Framework"
    source_url = "https://airc.nist.gov/RMF/1"

    async def fetch_state(self, client: httpx.AsyncClient) -> SourceState:
        rules: dict[str, Any] = {}
        version_tag = "1.0"
        fetch_method, degraded, fetch_note = "nist-cprt", False, None

        try:
            rules, version_tag = await self._fetch_from_cprt(client)
        except Exception as exc:
            rules = self._hardcoded_core_framework()
            fetch_method, degraded = "bundled-fallback", True
            fetch_note = (
                f"NIST CPRT unavailable ({describe_error(exc)}); "
                "using the bundled core-framework snapshot, not live NIST data"
            )

        state = SourceState(
            source_id=self.source_id,
            source_name=self.source_name,
            source_url=self.source_url,
            version_tag=version_tag,
            rules=rules,
            fetch_method=fetch_method,
            degraded=degraded,
            fetch_note=fetch_note,
        )
        state.compute_hash()
        return state

    async def _fetch_from_cprt(
        self, client: httpx.AsyncClient
    ) -> tuple[dict[str, Any], str]:
        resp = await client.get(
            f"{_NIST_CPRT_URL}/framework/{_NIST_RMF_ID}/core",
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()

        rules: dict[str, Any] = {}
        for function in data.get("functions", []):
            fn_id = function.get("id", "")
            for category in function.get("categories", []):
                cat_id = category.get("id", "")
                for subcat in category.get("subcategories", []):
                    sc_id = subcat.get("id", "")
                    rule_id = f"NIST-{sc_id}"
                    rules[rule_id] = self.normalise_rules({
                        "title": subcat.get("description", "")[:80],
                        "description": subcat.get("description", ""),
                        "severity": self._function_severity(fn_id),
                        "category": f"{fn_id}.{cat_id}",
                        "function": fn_id,
                        "subcategory_id": sc_id,
                    })

        return rules, data.get("version", "1.0")

    def _hardcoded_core_framework(self) -> dict[str, Any]:
        entries = [
            ("GOVERN.1.1", "GOVERN", "Policies and processes for AI risk management are documented.", "critical"),
            ("GOVERN.1.2", "GOVERN", "Accountability structures for AI risk are defined.", "critical"),
            ("GOVERN.1.3", "GOVERN", "AI risk tolerance is established and communicated.", "warning"),
            ("GOVERN.1.4", "GOVERN", "Organisational teams are committed to AI risk management.", "warning"),
            ("GOVERN.1.5", "GOVERN", "AI risk management frameworks are aligned with org risk management.", "warning"),
            ("GOVERN.1.6", "GOVERN", "AI risk management policies are periodically reviewed.", "info"),
            ("GOVERN.1.7", "GOVERN", "Processes for decommissioning AI systems are established.", "info"),
            ("GOVERN.2.1", "GOVERN", "Roles for AI risk management are clearly defined.", "critical"),
            ("GOVERN.2.2", "GOVERN", "AI risk management roles have adequate training.", "warning"),
            ("GOVERN.4.1", "GOVERN", "Organisational AI risk management processes are communicated.", "warning"),
            ("GOVERN.5.1", "GOVERN", "AI risk management policies include third-party considerations.", "warning"),
            ("GOVERN.6.1", "GOVERN", "Policies for AI risk management are enforced.", "critical"),
            ("GOVERN.6.2", "GOVERN", "Contingency plans for AI failures are maintained.", "critical"),
            ("MAP.1.1",    "MAP",    "AI use cases are clearly defined and documented.", "warning"),
            ("MAP.1.5",    "MAP",    "Organisational risk tolerances are applied to AI systems.", "critical"),
            ("MAP.2.1",    "MAP",    "Scientific findings for AI system risks are reviewed.", "warning"),
            ("MAP.2.2",    "MAP",    "AI system risks are identified through formal assessment.", "critical"),
            ("MAP.3.1",    "MAP",    "AI deployment context is evaluated for risks.", "warning"),
            ("MAP.5.1",    "MAP",    "Likelihood of AI risk impacts is assessed.", "critical"),
            ("MAP.5.2",    "MAP",    "AI risks are prioritised for response.", "critical"),
            ("MEASURE.1.1","MEASURE","AI risk measurement approaches are defined.", "warning"),
            ("MEASURE.2.1","MEASURE","Approaches for AI system testing are documented.", "critical"),
            ("MEASURE.2.5","MEASURE","AI system provenance is traced and documented.", "critical"),
            ("MEASURE.2.6","MEASURE","AI system risks are measured at regular intervals.", "warning"),
            ("MEASURE.4.1","MEASURE","Measurement approaches for AI risks are reviewed.", "info"),
            ("MANAGE.1.1", "MANAGE", "AI risk responses are developed and documented.", "critical"),
            ("MANAGE.1.3", "MANAGE", "Responses to AI risks are prioritised.", "critical"),
            ("MANAGE.2.1", "MANAGE", "AI system mechanisms are monitored for performance.", "critical"),
            ("MANAGE.2.4", "MANAGE", "AI risk treatments are tracked for effectiveness.", "warning"),
            ("MANAGE.3.1", "MANAGE", "AI risk responses include deactivation options.", "critical"),
            ("MANAGE.4.1", "MANAGE", "AI system risks are monitored continuously.", "critical"),
        ]
        rules: dict[str, Any] = {}
        for sc_id, fn_id, desc, severity in entries:
            rules[f"NIST-{sc_id}"] = self.normalise_rules({
                "title": desc[:80],
                "description": desc,
                "severity": severity,
                "category": fn_id,
                "function": fn_id,
                "subcategory_id": sc_id,
            })
        return rules

    def _function_severity(self, function_id: str) -> str:
        return {"GOVERN": "critical", "MAP": "critical",
                "MEASURE": "warning", "MANAGE": "critical"}.get(
            function_id.upper(), "warning"
        )

    def normalise_rules(self, raw: Any) -> dict[str, Any]:
        return {
            "title": raw.get("title", ""),
            "description": raw.get("description", ""),
            "severity": raw.get("severity", "warning"),
            "category": raw.get("category", ""),
            "regulatory_refs": ["NIST-AI-RMF-1.0"],
            "version": "1.0",
            "function": raw.get("function", ""),
            "subcategory_id": raw.get("subcategory_id", ""),
        }