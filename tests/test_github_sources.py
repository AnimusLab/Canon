"""Offline tests for the rate-limit-free fetch layer (no network)."""
import io
import zipfile

import httpx
import pytest

from canon.diff.engine import diff_states
from canon.models import SourceState
from canon.sources.finos import FINOSAdapter
from canon.sources.github_fetch import (
    SourceFetchError,
    content_hash,
    describe_error,
    download_archive,
    get_head_sha,
    is_rate_limited,
)
from canon.sources.owasp import OWASPAdapter

SHA = "a" * 40


def _client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True)


def _status_error(code, headers=None):
    req = httpx.Request("GET", "https://api.github.com/x")
    return httpx.HTTPStatusError("e", request=req, response=httpx.Response(code, headers=headers or {}, request=req))


# ---- helpers -------------------------------------------------------------------
def test_rate_limit_detection():
    assert is_rate_limited(_status_error(429))
    assert is_rate_limited(_status_error(403, {"x-ratelimit-remaining": "0"}))
    assert not is_rate_limited(_status_error(403))          # plain forbidden
    assert not is_rate_limited(_status_error(404))
    assert not is_rate_limited(ValueError("x"))


def test_describe_error_is_actionable():
    assert "GITHUB_TOKEN" in describe_error(_status_error(403, {"x-ratelimit-remaining": "0"}))
    assert "HTTP 404" in describe_error(_status_error(404))
    assert "network error" in describe_error(httpx.ConnectError("boom"))


@pytest.mark.anyio
async def test_get_head_sha_parses_pkt_lines():
    body = (
        b"001e# service=git-upload-pack\n0000"
        + f"00a1{SHA} HEAD\x00multi_ack symref=HEAD:refs/heads/main\n".encode()
        + f"003d{'b' * 40} refs/heads/dev\n".encode()
        + f"003d{SHA} refs/heads/main\n0000".encode()
    )
    async with _client(lambda r: httpx.Response(200, content=body)) as c:
        assert await get_head_sha(c, "o/r") == SHA
        with pytest.raises(SourceFetchError):
            await get_head_sha(c, "o/r", "nope")


def _zip(files: dict[str, str], comment: str = SHA) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.comment = comment.encode()
        for name, text in files.items():
            z.writestr(name, text)
    return buf.getvalue()


@pytest.mark.anyio
async def test_archive_size_limit(monkeypatch):
    monkeypatch.setattr("canon.sources.github_fetch.MAX_ARCHIVE_BYTES", 100)
    async with _client(lambda r: httpx.Response(200, content=b"x" * 5000)) as c:
        with pytest.raises(SourceFetchError, match="exceeds"):
            await download_archive(c, "o/r")


# ---- FINOS ---------------------------------------------------------------------
_RISK = """---
sequence: 10
title: Prompt Injection
type: SEC
doc-status: Approved-Specification
---

## Summary

Attackers craft inputs
that manipulate the model.

## Description

Long text.
"""


@pytest.mark.anyio
async def test_finos_reads_jekyll_risks_from_archive():
    data = _zip({
        "repo-main/docs/_risks/ri-10_prompt-injection.md": _RISK,
        "repo-main/docs/_risks/nested/ri-99_x.md": _RISK,          # not a direct child
        "repo-main/docs/_mitigations/mi-1_x.md": _RISK,            # other collection
        "repo-main/docs/risks/ri-5_legacy-path.md": _RISK,         # the old, wrong path
    })
    seen = []

    def handler(req):
        seen.append(str(req.url))
        return httpx.Response(200, content=data)

    async with _client(handler) as c:
        state = await FINOSAdapter().fetch_state(c)

    assert seen == ["https://codeload.github.com/finos/ai-governance-framework/zip/refs/heads/main"]
    assert state.commit_sha == SHA and state.fetch_method == "github-archive"
    assert list(state.rules) == ["FINOS-RI-10"]                    # stable id, no slug
    r = state.rules["FINOS-RI-10"]
    assert r["title"] == "Prompt Injection" and r["category"] == "security"
    assert r["description"] == "Attackers craft inputs that manipulate the model."
    assert r["doc_status"] == "Approved-Specification" and r["content_hash"]


@pytest.mark.anyio
async def test_content_edit_outside_extracted_fields_is_detected():
    """An edit deep in the body must still produce evidence (content_hash)."""
    async def state_for(text):
        data = _zip({"repo-main/docs/_risks/ri-10_x.md": text})
        async with _client(lambda r: httpx.Response(200, content=data)) as c:
            return await FINOSAdapter().fetch_state(c)

    before = await state_for(_RISK)
    after = await state_for(_RISK.replace("Long text.", "Long text, now with new guidance."))
    pkg = diff_states(before, after)
    assert pkg.change_count == 1
    assert "content_hash" in pkg.diffs[0].description


def test_content_hash_ignores_line_endings_and_edge_whitespace():
    assert content_hash("a\r\nb\n") == content_hash("a\nb")


# ---- OWASP ---------------------------------------------------------------------
def _owasp_handler(api_status, raw_missing=()):
    calls = {"api": 0, "raw": 0}

    def handler(req):
        url = str(req.url)
        if url.startswith("https://api.github.com"):
            calls["api"] += 1
            hdr = {"x-ratelimit-remaining": "0"} if api_status == 403 else {}
            return httpx.Response(api_status, headers=hdr, json={"message": "limit"})
        if "info/refs" in url:
            return httpx.Response(200, content=f"003d{SHA} refs/heads/main\n".encode())
        if url.startswith("https://raw.githubusercontent.com"):
            calls["raw"] += 1
            path = url.split(f"/{SHA}/", 1)[1]
            if any(m in path for m in raw_missing):
                return httpx.Response(404)
            if path == "changes.md":
                return httpx.Response(200, text="## 2.0.0\nnotes")
            llm = path.split("/")[-1][:5]
            return httpx.Response(200, text=f"## {llm}:2025 Title\n\n### Description\n\nBody of {llm}.\n")
        return httpx.Response(500)

    return handler, calls


@pytest.mark.anyio
async def test_owasp_falls_back_without_api_when_rate_limited():
    handler, calls = _owasp_handler(403)
    async with _client(handler) as c:
        state = await OWASPAdapter().fetch_state(c)
    assert state.fetch_method == "raw-manifest" and "GITHUB_TOKEN" in state.fetch_note
    assert state.commit_sha == SHA and state.version_tag == "2.0.0"
    assert set(state.rules) == {f"OWASP-LLM{n:02d}" for n in range(0, 11)}
    assert state.rules["OWASP-LLM03"]["description"] == "Body of LLM03."
    assert calls["api"] == 1  # one probe, then no more API use


@pytest.mark.anyio
async def test_owasp_stale_manifest_is_an_error_not_a_silent_drop():
    handler, _ = _owasp_handler(403, raw_missing=("LLM05",))
    async with _client(handler) as c:
        with pytest.raises(SourceFetchError, match="stale"):
            await OWASPAdapter().fetch_state(c)


@pytest.mark.anyio
async def test_owasp_non_rate_limit_error_is_not_masked():
    handler, _ = _owasp_handler(404)
    async with _client(handler) as c:
        with pytest.raises(httpx.HTTPStatusError):
            await OWASPAdapter().fetch_state(c)
