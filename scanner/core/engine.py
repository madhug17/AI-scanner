
from pathlib import Path
from typing import Protocol

from scanner.core.finding import Finding


SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".next",
    "dist",
    "build",
}

MAX_FILE_SIZE = 1_000_000  # 1 MB

SOURCE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx",
    ".json", ".yaml", ".yml", ".toml",
    ".env", ".html", ".tf", ".sh",
    ".dockerfile",
}


class SecurityRule(Protocol):
    rule_id: str

    def scan(
        self,
        file_path: str,
        content: str
    ) -> list[Finding]:
        ...


class SecurityEngine:

    def __init__(self, rules: list[SecurityRule]):
        self.rules = rules

    def scan_repository(self, repo_path: str) -> list[Finding]:

        root = Path(repo_path).resolve()
        findings = []

        for file in root.rglob("*"):

            if not file.is_file():
                continue

            if any(part in SKIP_DIRS for part in file.parts):
                continue
            if file.suffix.lower() not in SOURCE_EXTENSIONS:
                continue
            try:
                if file.stat().st_size > MAX_FILE_SIZE:
                    continue

                content = file.read_text(
                    encoding="utf-8",
                    errors="replace"
                )
                relative_path = str(file.relative_to(root))
                for rule in self.rules:
                    results = rule.scan(
                        relative_path,
                        content
                    )
                    findings.extend(results)
            except (OSError, ValueError):
                continue
        return findings
