from pathlib import Path
from pydantic import BaseModel, Field

SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    ".next",
    ".nuxt",
    "dist",
    "build",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "target",
}

MAX_FILE_SIZE_BYTES = 1_000_000  # 1 MB

SUPPORTED_EXTENSIONS = {
    # Python
    ".py": "python",
    # JavaScript & TypeScript
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    # Config & Markup
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".env": "env",
    ".html": "html",
    # Infrastructure
    ".tf": "terraform",
    ".dockerfile": "dockerfile",
    ".sh": "shell",
    ".sql": "sql",
}

KNOWN_FILENAMES = {
    "dockerfile": "dockerfile",
    "requirements.txt": "python_requirements",
    "pipfile": "python_requirements",
    "pyproject.toml": "toml",
    "package.json": "json",
}


class DiscoveredFile(BaseModel):
    path: Path
    relative_path: str
    language: str
    size_bytes: int


def discover_files(
    repo_root: Path | str,
    max_file_size: int = MAX_FILE_SIZE_BYTES,
) -> tuple[list[DiscoveredFile], list[str]]:
    """Discover candidate source and configuration files safely in the repository.
    
    Returns:
        tuple of (discovered_files, skipped_or_error_files)
    """
    root = Path(repo_root).resolve()
    if not root.exists() or not root.is_dir():
        raise NotADirectoryError(f"Repository root is not a valid directory: {root}")

    discovered: list[DiscoveredFile] = []
    skipped: list[str] = []

    for file_path in root.rglob("*"):
        try:
            # Resolve to prevent symlink path traversal attacks
            resolved = file_path.resolve()
            if not resolved.is_relative_to(root):
                skipped.append(f"{file_path}: Symlink points outside repository boundary")
                continue

            if not resolved.is_file():
                continue

            # Check if within any skip directory
            if any(part in SKIP_DIRS for part in resolved.parts):
                continue

            # Determine file type
            fname_lower = resolved.name.lower()
            ext = resolved.suffix.lower()

            language = None
            if fname_lower in KNOWN_FILENAMES:
                language = KNOWN_FILENAMES[fname_lower]
            elif ext in SUPPORTED_EXTENSIONS:
                language = SUPPORTED_EXTENSIONS[ext]

            if not language:
                continue

            # Check file size
            file_size = resolved.stat().st_size
            if file_size > max_file_size:
                skipped.append(f"{file_path}: Exceeds maximum size of {max_file_size} bytes")
                continue

            rel_path = str(resolved.relative_to(root)).replace("\\", "/")
            discovered.append(
                DiscoveredFile(
                    path=resolved,
                    relative_path=rel_path,
                    language=language,
                    size_bytes=file_size,
                )
            )

        except (OSError, ValueError) as err:
            skipped.append(f"{file_path}: {err}")

    return discovered, skipped

