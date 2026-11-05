import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any
import requests

from scanner.core.config import settings
from scanner.analyzers.result_normalizer import AnalyzerResult, normalize_dependency_finding
from scanner.rules.dependencies.rules import KNOWN_VULNERABLE_PACKAGES


class DependencyAuditAnalyzer:
    def __init__(self, binary_path: str | None = None, osv_url: str | None = None):
        self.binary_path = binary_path or settings.pip_audit_binary
        self.osv_url = osv_url or settings.osv_api_url

    def is_pip_audit_available(self) -> bool:
        return shutil.which(self.binary_path) is not None

    def parse_requirements(self, req_path: Path) -> list[tuple[str, str, int]]:
        """Extract (package_name, version, line_number) from requirements.txt."""
        packages = []
        if not req_path.exists():
            return packages

        pattern = re.compile(r"^([a-zA-Z0-9_\-\.]+)\s*==\s*([0-9a-zA-Z\.\-]+)")
        for line_no, line in enumerate(req_path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            clean = line.strip()
            match = pattern.match(clean)
            if match:
                packages.append((match.group(1).lower(), match.group(2), line_no))
        return packages

    def check_osv_package(self, package_name: str, version: str) -> list[dict[str, Any]]:
        """Query the Google OSV API for known vulnerabilities affecting package & version."""
        try:
            payload = {
                "package": {"name": package_name, "ecosystem": "PyPI"},
                "version": version,
            }
            resp = requests.post(self.osv_url, json=payload, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("vulns", [])
        except Exception:
            pass
        return []

    def run(self, repo_path: Path, timeout_sec: int = 60) -> AnalyzerResult:
        # Find requirements.txt files
        req_files = list(repo_path.glob("**/requirements*.txt"))
        if not req_files:
            return AnalyzerResult(
                tool_name="dependency-audit",
                success=True,
                findings=[],
            )

        # 1. Try pip-audit CLI if installed
        if self.is_pip_audit_available():
            try:
                cmd = [
                    self.binary_path,
                    "-r", str(req_files[0]),
                    "-f", "json",
                ]
                res = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout_sec,
                )
                if res.returncode in {0, 1}:
                    data = json.loads(res.stdout or "{}")
                    findings = []
                    dep_entries = data.get("dependencies", [])
                    for dep in dep_entries:
                        name = dep.get("name")
                        ver = dep.get("version")
                        for vuln in dep.get("vulns", []):
                            vuln_id = vuln.get("id", "VULN")
                            desc = vuln.get("description", "")
                            findings.append(
                                normalize_dependency_finding(
                                    package_name=name,
                                    installed_version=ver,
                                    advisory_id=vuln_id,
                                    details=desc,
                                    file_path=str(req_files[0].relative_to(repo_path)),
                                )
                            )
                    return AnalyzerResult(
                        tool_name="dependency-audit",
                        success=True,
                        findings=findings,
                    )
            except Exception:
                pass

        # 2. Query OSV / built-in vulnerability database
        findings = []
        errors = []
        for req_file in req_files:
            rel_file = str(req_file.relative_to(repo_path)).replace("\\", "/")
            parsed_pkgs = self.parse_requirements(req_file)
            for pkg, ver, line_no in parsed_pkgs:
                # First check built-in known vulnerable table
                if pkg in KNOWN_VULNERABLE_PACKAGES and ver in KNOWN_VULNERABLE_PACKAGES[pkg]:
                    cve = KNOWN_VULNERABLE_PACKAGES[pkg][ver]
                    findings.append(
                        normalize_dependency_finding(
                            package_name=pkg,
                            installed_version=ver,
                            advisory_id=cve,
                            details="Matched known critical vulnerability catalog",
                            file_path=rel_file,
                            line_start=line_no,
                        )
                    )
                    continue

                # Query OSV API if online
                osv_vulns = self.check_osv_package(pkg, ver)
                for v in osv_vulns:
                    vid = v.get("id", "UNKNOWN-VULN")
                    summary = v.get("summary", "")
                    findings.append(
                        normalize_dependency_finding(
                            package_name=pkg,
                            installed_version=ver,
                            advisory_id=vid,
                            details=summary,
                            file_path=rel_file,
                            line_start=line_no,
                        )
                    )

        return AnalyzerResult(
            tool_name="dependency-audit",
            success=True,
            findings=findings,
        )

