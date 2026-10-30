"""
Rate-limit-free helpers for reading public GitHub-hosted sources.

Why this exists: the GitHub REST API allows only 60 unauthenticated requests per
hour per IP. Canon only needs public content, which GitHub also serves through
endpoints that are not part of that quota:

  - git smart-HTTP  (github.com/<repo>.git/info/refs)  -> commit SHA of a branch
  - raw content     (raw.githubusercontent.com/...)    -> file bytes at a pinned SHA
  - repo archive    (codeload.github.com/...)          -> whole repo as one zip,
                                                          commit SHA in the zip comment
"""
from __future__ import annotations

import hashlib
import io
import re
import zipfile

import httpx

_SHA_RE = re.compile(r"\b([0-9a-f]{40})\b")
_REF_LINE_RE = re.compile(r"([0-9a-f]{40}) (refs/[^\x00\n]+)")

MAX_ARCHIVE_BYTES = 25 * 1024 * 1024   # refuse surprise-sized archives
MAX_FILE_BYTES = 2 * 1024 * 1024       # per extracted file


class SourceFetchError(Exception):
    """A source could not be fetched safely. Message is user-presentable."""


def is_rate_limited(exc: Exception) -> bool:
    if not isinstance(exc, httpx.HTTPStatusError):
        return False
    r = exc.response
    if r.status_code == 429:
        return True
    return r.status_code == 403 and (
        r.headers.get("x-ratelimit-remaining") == "0" or "retry-after" in r.headers
    )


def describe_error(exc: BaseException) -> str:
    """One-line, actionable description of a fetch failure."""
    if is_rate_limited(exc):  # type: ignore[arg-type]
        return (
            "GitHub API rate limit reached. Set GITHUB_TOKEN "
            "(or pass --github-token) to raise the limit."
        )
    if isinstance(exc, httpx.HTTPStatusError):
        return f"HTTP {exc.response.status_code} from {exc.request.url}"
    if isinstance(exc, httpx.RequestError):
        return f"network error ({type(exc).__name__}): {exc}"
    if isinstance(exc, SourceFetchError):
        return str(exc)
    return f"{type(exc).__name__}: {exc}"


async def get_head_sha(client: httpx.AsyncClient, repo: str, branch: str = "main") -> str:
    """Commit SHA of a branch via git smart-HTTP; does not use the REST API quota."""
    url = f"https://github.com/{repo}.git/info/refs?service=git-upload-pack"
    resp = await client.get(url, timeout=30)
    resp.raise_for_status()
    wanted = f"refs/heads/{branch}"
    for sha, ref in _REF_LINE_RE.findall(resp.content.decode("latin-1")):
        if ref == wanted:
            return sha
    raise SourceFetchError(f"branch '{branch}' not found in {repo}")


async def get_raw(client: httpx.AsyncClient, repo: str, sha: str, path: str) -> str:
    url = f"https://raw.githubusercontent.com/{repo}/{sha}/{path}"
    resp = await client.get(url, timeout=30)
    resp.raise_for_status()
    return resp.text


async def download_archive(
    client: httpx.AsyncClient, repo: str, branch: str = "main"
) -> tuple[str, zipfile.ZipFile]:
    """
    Download the branch archive. Returns (commit_sha, ZipFile).
    The commit SHA is read from the zip comment GitHub embeds; if absent, it is
    resolved via get_head_sha().
    """
    url = f"https://codeload.github.com/{repo}/zip/refs/heads/{branch}"
    buf = bytearray()
    async with client.stream("GET", url, timeout=60) as resp:
        resp.raise_for_status()
        async for chunk in resp.aiter_bytes():
            buf += chunk
            if len(buf) > MAX_ARCHIVE_BYTES:
                raise SourceFetchError(
                    f"{repo} archive exceeds {MAX_ARCHIVE_BYTES // (1024 * 1024)} MB limit"
                )
    try:
        zf = zipfile.ZipFile(io.BytesIO(bytes(buf)))
    except zipfile.BadZipFile as exc:
        raise SourceFetchError(f"{repo} archive is not a valid zip") from exc
    m = _SHA_RE.search(zf.comment.decode("latin-1"))
    sha = m.group(1) if m else await get_head_sha(client, repo, branch)
    return sha, zf


def read_zip_text(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> str:
    if info.file_size > MAX_FILE_BYTES:
        raise SourceFetchError(f"{info.filename} is larger than {MAX_FILE_BYTES} bytes")
    return zf.read(info).decode("utf-8", errors="replace")


def content_hash(text: str) -> str:
    """SHA-256 of a source document, line-ending and edge-whitespace normalised.
    Lets Canon notice ANY edit to a rule's source text, not just the extracted fields."""
    return hashlib.sha256(text.replace("\r\n", "\n").strip().encode("utf-8")).hexdigest()
