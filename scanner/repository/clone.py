import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Generator
from contextlib import contextmanager

from scanner.core.config import settings
from scanner.repository.github import validate_and_parse_github_url


class RepositoryCloneError(Exception):
    """Raised when repository cloning fails or violates safety bounds."""
    pass


def get_dir_size_bytes(directory: Path) -> int:
    """Calculate the total size of files inside a directory."""
    total = 0
    try:
        for entry in directory.rglob("*"):
            if entry.is_file():
                total += entry.stat().st_size
    except OSError:
        pass
    return total


@contextmanager
def safe_clone_repository(
    repo_url: str,
    timeout_sec: int | None = None,
    max_size_mb: int | None = None,
) -> Generator[Path, None, None]:
    """Clone a GitHub repository into an isolated temporary directory with strict safety limits.
    
    Guarantees:
    - URL validation prevents argument injection and SSRF.
    - Isolated temporary directory created per scan.
    - Environment variables stripped to avoid leaking host credentials.
    - Shallow clone (--depth 1) to conserve bandwidth and memory.
    - Enforced process execution timeout.
    - Repository size ceiling enforced post-clone.
    - Cleaned up safely in finally block.
    """
    parsed = validate_and_parse_github_url(repo_url)
    timeout = timeout_sec or settings.max_repo_clone_timeout_sec
    max_mb = max_size_mb or settings.max_repo_size_mb

    temp_dir = tempfile.mkdtemp(prefix="sec_scan_")
    target_path = Path(temp_dir).resolve()

    try:
        # Sanitized isolated environment (prevent inheriting sensitive tokens)
        safe_env = {
            "PATH": os.environ.get("PATH", ""),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
            "TEMP": os.environ.get("TEMP", ""),
            "TMP": os.environ.get("TMP", ""),
            "GIT_TERMINAL_PROMPT": "0",  # Never prompt interactively for auth
        }

        # Safe git invocation with depth=1
        cmd = [
            "git",
            "clone",
            "--depth", "1",
            "--config", "core.hooksPath=/dev/null",  # Prevent malicious git hooks
            parsed.url,
            str(target_path),
        ]

        result = subprocess.run(
            cmd,
            env=safe_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )

        if result.returncode != 0:
            err_msg = result.stderr.strip() or "Git clone returned non-zero status"
            raise RepositoryCloneError(f"Failed to clone repository '{parsed.url}': {err_msg}")

        # Check repository size limit
        total_size_bytes = get_dir_size_bytes(target_path)
        if total_size_bytes > max_mb * 1024 * 1024:
            raise RepositoryCloneError(
                f"Repository exceeds maximum size limit of {max_mb} MB (actual: {total_size_bytes / (1024*1024):.1f} MB)"
            )

        yield target_path

    except subprocess.TimeoutExpired as exc:
        raise RepositoryCloneError(
            f"Repository cloning timed out after {timeout} seconds"
        ) from exc
    finally:
        # Clean temporary directory completely
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except OSError:
            pass

