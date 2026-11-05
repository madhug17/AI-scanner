import json
import shutil
import subprocess
from pathlib import Path
from scanner.core.config import settings
from scanner.analyzers.result_normalizer import AnalyzerResult, normalize_semgrep_finding


class SemgrepAnalyzer:
    def __init__(self, binary_path: str | None = None):
        self.binary_path = binary_path or settings.semgrep_binary

    def is_available(self) -> bool:
        return shutil.which(self.binary_path) is not None

    def run(self, repo_path: Path, timeout_sec: int = 60) -> AnalyzerResult:
        if not self.is_available():
            return AnalyzerResult(
                tool_name="semgrep",
                success=False,
                error_message=f"Semgrep executable '{self.binary_path}' not found on system path.",
                findings=[],
            )

        cmd = [
            self.binary_path,
            "scan",
            "--config", "auto",
            "--json",
            "--quiet",
            str(repo_path),
        ]

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_sec,
            )
            # Semgrep returns 0 on clean/findings, 1 or >1 on error
            if res.returncode not in {0, 1}:
                return AnalyzerResult(
                    tool_name="semgrep",
                    success=False,
                    error_message=f"Semgrep failed with return code {res.returncode}: {res.stderr.strip()}",
                    findings=[],
                )

            data = json.loads(res.stdout or "{}")
            raw_results = data.get("results", [])
            findings = [normalize_semgrep_finding(r, str(repo_path)) for r in raw_results]

            return AnalyzerResult(
                tool_name="semgrep",
                success=True,
                findings=findings,
            )

        except subprocess.TimeoutExpired:
            return AnalyzerResult(
                tool_name="semgrep",
                success=False,
                error_message=f"Semgrep execution timed out after {timeout_sec} seconds.",
                findings=[],
            )
        except json.JSONDecodeError as err:
            return AnalyzerResult(
                tool_name="semgrep",
                success=False,
                error_message=f"Invalid JSON returned by Semgrep: {err}",
                findings=[],
            )
        except Exception as err:
            return AnalyzerResult(
                tool_name="semgrep",
                success=False,
                error_message=f"Semgrep analyzer error: {err}",
                findings=[],
            )

