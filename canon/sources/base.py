"""
Canon source adapter interface.
Any governance source implements this. Domain agnostic.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any
import httpx

from canon.models import SourceState


class BaseSourceAdapter(ABC):
    source_id: str
    source_name: str
    source_url: str

    @abstractmethod
    async def fetch_state(self, client: httpx.AsyncClient) -> SourceState:
        ...

    @abstractmethod
    def normalise_rules(self, raw: Any) -> dict[str, Any]:
        """
        Normalise into Canon's common schema:
        {
            rule_id: {
                "title": str,
                "description": str,
                "severity": str,       # info | warning | critical
                "category": str,
                "regulatory_refs": [],
                "version": str,
            }
        }
        """
        ...