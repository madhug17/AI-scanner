import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from scanner.core.config import settings
from scanner.analyzers.result_normalizer import AnalyzerResult, normalize_gitleaks_finding


class GitleaksAnalyzer:
    def __init__(self, binary_path: str | None = None):
        self.binary_path = binary_path or settings.gitleaks_binary

    def is_available(self) -> bool:
        return shutil.which(self.binary_path) is not None

    def run(self, repo_path: Path, scan_history: bool = True, timeout_sec: int = 60) -> AnalyzerResult:
        if not self.is_available():
            return AnalyzerResult(
                tool_name="gitleaks",
                success=False,
                error_message=f"Gitleaks executable '{self.binary_path}' not found on system path.",
                findings=[],
            )

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as report_file:
            report_path = report_file.name

        try:
            cmd = [
                self.binary_path,
                "detect",
                "--source", str(repo_path),
                "--report-path", report_path,
                "--report-format", "json",
            ]
            if not scan_history or not (repo_path / ".git").exists():
                cmd.append("--no-git")

            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_sec,
            )

            # Gitleaks exits with 0 (no leaks) or 1 (leaks found). Any other code is a crash/error.
            if res.returncode not in {0, 1}:
                return AnalyzerResult(
                    tool_name="gitleaks",
                    success=False,
                    error_message=f"Gitleaks failed with exit code {res.returncode}: {res.stderr.strip()}",
                    findings=[],
                )

            report_file_path = Path(report_path)
            if report_file_path.exists() and report_file_path.stat().st_size > 0:
                raw_data = json.loads(report_file_path.read_text(encoding="utf-8"))
                findings = [normalize_gitleaks_finding(item) for item in raw_data]
            else:
                findings = []

            return AnalyzerResult(
                tool_name="gitleaks",
                success=True,
                findings=findings,
            )

        except subprocess.TimeoutExpired:
            return AnalyzerResult(
                tool_name="gitleaks",
                success=False,
                error_message=f"Gitleaks execution timed out after {timeout_sec} seconds.",
                findings=[],
            )
        except json.JSONDecodeError as err:
            return AnalyzerResult(
                tool_name="gitleaks",
                success=False,
                error_message=f"Invalid JSON returned by Gitleaks: {err}",
                findings=[],
            )
        except Exception as err:
            return AnalyzerResult(
                tool_name="gitleaks",
                success=False,
                error_message=f"Gitleaks analyzer error: {err}",
                findings=[],
            )
        finally:
            try:
                Path(report_path).unlink(missing_ok=True)
            except OSError:
                pass

