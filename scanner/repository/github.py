import re
from urllib.parse import urlparse
from pydantic import BaseModel, HttpUrl, field_validator


GITHUB_URL_REGEX = re.compile(
    r"^https://github\.com/([a-zA-Z0-9_.-]+)/([a-zA-Z0-9_.-]+?)(?:\.git)?/?$"
)


class ParsedRepoInfo(BaseModel):
    url: str
    owner: str
    name: str


def validate_and_parse_github_url(url_str: str) -> ParsedRepoInfo:
    """Validate that the URL is a legitimate GitHub repository URL and extract owner and repo name.
    
    Rejects:
    - Non-HTTPS schemes (e.g. git://, ssh://, file://, http://)
    - Non-github.com hosts (prevents SSRF / internal IP scanning)
    - URL credentials (e.g. https://user:pass@github.com/...)
    - Path traversal or shell control characters
    """
    if not isinstance(url_str, str):
        raise ValueError("Repository URL must be a string")

    cleaned = url_str.strip()
    
    # Reject shell injection characters and whitespace
    if any(ch in cleaned for ch in [";", "&", "|", "`", "$", " ", "\n", "\r", "\t", "<", ">"]):
        raise ValueError("Invalid characters detected in repository URL")

    parsed = urlparse(cleaned)

    if parsed.scheme.lower() != "https":
        raise ValueError("Only HTTPS GitHub URLs are supported (e.g., https://github.com/owner/repo)")

    if parsed.username or parsed.password:
        raise ValueError("Embedded credentials in repository URL are prohibited")

    hostname = (parsed.hostname or "").lower()
    if hostname != "github.com":
        raise ValueError("Only repositories hosted directly on github.com are allowed")

    match = GITHUB_URL_REGEX.match(cleaned)
    if not match:
        raise ValueError(
            "Repository URL format invalid. Expected: https://github.com/<owner>/<repo>"
        )

    owner = match.group(1)
    name = match.group(2)

    # Prevent path traversal components in owner or repo name
    if owner in {".", ".."} or name in {".", ".."}:
        raise ValueError("Invalid owner or repository name")

    canonical_url = f"https://github.com/{owner}/{name}"
    return ParsedRepoInfo(url=canonical_url, owner=owner, name=name)

