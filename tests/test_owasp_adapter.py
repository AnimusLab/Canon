import pytest
from unittest.mock import AsyncMock, MagicMock
import httpx
from canon.sources.owasp import OWASPAdapter

@pytest.mark.anyio
async def test_owasp_adapter_excludes_translations():
    adapter = OWASPAdapter()
    
    # Mock httpx Client
    client = MagicMock(spec=httpx.AsyncClient)
    
    # Mock responses
    # 1. Commit response
    commit_response = MagicMock(spec=httpx.Response)
    commit_response.json.return_value = {"sha": "mock-sha"}
    commit_response.status_code = 200
    
    # 2. Tree response containing a valid rule, a translation rule, and a non-md file
    tree_response = MagicMock(spec=httpx.Response)
    tree_response.json.return_value = {
        "tree": [
            {
                "path": "2_0_vulns/LLM01_PromptInjection.md",
                "type": "blob"
            },
            {
                "path": "2_0_vulns/translations/ko-KR/LLM02_SensitiveInformationDisclosure.md",
                "type": "blob"
            },
            {
                "path": "2_0_vulns/some_image.png",
                "type": "blob"
            }
        ]
    }
    tree_response.status_code = 200
    
    # 3. Raw file fetch response
    raw_response = MagicMock(spec=httpx.Response)
    raw_response.text = "# LLM01: Prompt Injection\nDescription of prompt injection."
    raw_response.status_code = 200
    
    # 4. Changelog response (for version detection)
    changelog_response = MagicMock(spec=httpx.Response)
    changelog_response.text = "## 2.0.0\nInitial release"
    changelog_response.status_code = 200
    
    # Setup mock behavior
    async def mock_get(url, *args, **kwargs):
        if "commits/main" in url:
            return commit_response
        elif "git/trees" in url:
            return tree_response
        elif "raw.githubusercontent.com" in url:
            if "changelog" in url.lower() or "changes" in url.lower():
                return changelog_response
            return raw_response
        raise ValueError(f"Unexpected URL: {url}")
        
    client.get = AsyncMock(side_effect=mock_get)
    
    state = await adapter.fetch_state(client)
    
    # Assertions
    assert state.commit_sha == "mock-sha"
    
    # OWASP-LLM01 should be processed
    assert "OWASP-LLM01" in state.rules
    
    # OWASP-LLM02 (ko-KR translation) should NOT be parsed/processed
    assert "OWASP-LLM02" not in state.rules
    
    # The rule title and description should be correctly extracted
    rule = state.rules["OWASP-LLM01"]
    assert rule["title"] == "LLM01: Prompt Injection"
    assert "Description of prompt injection" in rule["description"]
