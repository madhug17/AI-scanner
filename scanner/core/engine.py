
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

        if not root.exists():
            raise FileNotFoundError(
                f"Repository path does not exist: {root}"
            )

        if not root.is_dir():
            raise NotADirectoryError(
                f"Expected a directory: {root}"
            )

        findings: list[Finding] = []

        print(f"\n[SCAN] Scanning repository: {root}\n")

        scanned_files = 0
        skipped_files = 0
        rule_errors = 0

        for file in root.rglob("*"):

            if not file.is_file():
                continue

            # Skip unnecessary directories
            if any(part in SKIP_DIRS for part in file.parts):
                continue

            # Check supported file extensions
            if file.suffix.lower() not in SOURCE_EXTENSIONS:
                continue

            try:
                # Skip very large files
                if file.stat().st_size > MAX_FILE_SIZE:
                    skipped_files += 1
                    continue

                # Read file
                content = file.read_text(
                    encoding="utf-8",
                    errors="replace"
                )

                relative_path = str(file.relative_to(root))

                scanned_files += 1

                # Execute all security rules
                for rule in self.rules:

                    try:
                        results = rule.scan(
                            relative_path,
                            content
                        )

                        # Validate detector output
                        if results is None:
                            raise TypeError(
                                f"Rule {rule.rule_id} returned None"
                            )

                        if not isinstance(results, list):
                            raise TypeError(
                                f"Rule {rule.rule_id} must return a list"
                            )

                        for finding in results:
                            if not isinstance(finding, Finding):
                                raise TypeError(
                                    f"Rule {rule.rule_id} returned "
                                    "an invalid finding object"
                                )

                        findings.extend(results)

                    except Exception as error:
                        rule_errors += 1
                        print(
                            f"[RULE ERROR] {rule.rule_id} | "
                            f"{relative_path} | {error}"
                        )

            except (OSError, ValueError) as error:
                skipped_files += 1
                print(f"[FILE ERROR] {file}: {error}")

        print("\n========== SCAN SUMMARY ==========")
        print(f"Files scanned: {scanned_files}")
        print(f"Files skipped: {skipped_files}")
        print(f"Security findings: {len(findings)}")
        print(f"Rule errors: {rule_errors}")
        print("==================================\n")

        return findings
