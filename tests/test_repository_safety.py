import pytest
from pathlib import Path
from scanner.repository.github import validate_and_parse_github_url
from scanner.repository.clone import safe_clone_repository, RepositoryCloneError


def test_valid_github_urls():
    info1 = validate_and_parse_github_url("https://github.com/fastapi/fastapi")
    assert info1.owner == "fastapi"
    assert info1.name == "fastapi"
    assert info1.url == "https://github.com/fastapi/fastapi"

    info2 = validate_and_parse_github_url("https://github.com/owner/my-repo.git/")
    assert info2.owner == "owner"
    assert info2.name == "my-repo"


def test_reject_insecure_schemes():
    with pytest.raises(ValueError, match="Only HTTPS GitHub URLs"):
        validate_and_parse_github_url("http://github.com/owner/repo")

    with pytest.raises(ValueError, match="Only HTTPS GitHub URLs"):
        validate_and_parse_github_url("git@github.com:owner/repo.git")

    with pytest.raises(ValueError, match="Only HTTPS GitHub URLs"):
        validate_and_parse_github_url("file:///etc/passwd")


def test_reject_non_github_and_internal_ips():
    with pytest.raises(ValueError, match="Only repositories hosted directly on github.com"):
        validate_and_parse_github_url("https://gitlab.com/owner/repo")

    with pytest.raises(ValueError, match="Only repositories hosted directly on github.com"):
        validate_and_parse_github_url("https://169.254.169.254/latest/meta-data")

    with pytest.raises(ValueError, match="Only repositories hosted directly on github.com"):
        validate_and_parse_github_url("https://localhost/owner/repo")


def test_reject_embedded_credentials():
    with pytest.raises(ValueError, match="Embedded credentials"):
        validate_and_parse_github_url("https://user:password@github.com/owner/repo")


def test_reject_shell_injection_characters():
    with pytest.raises(ValueError, match="Invalid characters"):
        validate_and_parse_github_url("https://github.com/owner/repo; rm -rf /")

    with pytest.raises(ValueError, match="Invalid characters"):
        validate_and_parse_github_url("https://github.com/owner/repo | curl attacker.com")


def test_clone_nonexistent_repo_raises_error():
    with pytest.raises(RepositoryCloneError):
        with safe_clone_repository("https://github.com/this-owner-should-not-exist-xyz/repo-12345", timeout_sec=5):
            pass

