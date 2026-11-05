import sys
import json
import argparse
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from scanner.core.config import settings
from scanner.core.engine import SecurityEngine
from scanner.core.registry import default_registry
from scanner.database.session import init_db
from scanner.api.routes import health, scans, reports, auth, repositories, findings


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables on startup
    init_db()
    yield


app = FastAPI(
    title=settings.app_name,
    version=settings.scan_version,
    description="Backend API for AI App Security & Quality Scanner",
    lifespan=lifespan,
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers (supporting both canonical /api/v1/ and root path endpoints)
app.include_router(health.router)
app.include_router(auth.router, prefix="/api/v1")
app.include_router(auth.router)
app.include_router(repositories.router, prefix="/api/v1")
app.include_router(repositories.router)
app.include_router(scans.router)
app.include_router(scans.router, prefix="", tags=["Scans (Root)"])
app.include_router(reports.router)
app.include_router(reports.router, prefix="", tags=["Reports (Root)"])
app.include_router(findings.router, prefix="/api/v1")
app.include_router(findings.router)

# Mount Frontend Static Assets
frontend_dir = Path(__file__).resolve().parent.parent / "frontend"
if frontend_dir.exists():
    css_dir = frontend_dir / "css"
    js_dir = frontend_dir / "js"
    if css_dir.exists():
        app.mount("/css", StaticFiles(directory=str(css_dir)), name="css")
    if js_dir.exists():
        app.mount("/js", StaticFiles(directory=str(js_dir)), name="js")

    @app.get("/", include_in_schema=False)
    @app.get("/dashboard", include_in_schema=False)
    def serve_frontend_index():
        return FileResponse(str(frontend_dir / "index.html"))


def main():
    parser = argparse.ArgumentParser(
        description="AI Application Security & Quality Scanner CLI"
    )
    parser.add_argument(
        "repository",
        help="Path to the repository to scan",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output full JSON report",
    )
    parser.add_argument(
        "--no-external",
        action="store_true",
        help="Skip external analyzers (Semgrep, Gitleaks, etc.)",
    )
    args = parser.parse_args()

    engine = SecurityEngine()
    result = engine.execute_scan(
        args.repository,
        run_external_tools=not args.no_external,
    )

    findings_json = [f.model_dump(mode="json") for f in result.findings]

    if args.json:
        full_report = {
            "scanned_files": result.scanned_files_count,
            "skipped_files": result.skipped_files_count,
            "scan_complete": result.scan_complete,
            "tool_errors": result.tool_errors,
            "summary": result.summary.model_dump(mode="json") if result.summary else None,
            "findings": findings_json,
        }
        print(json.dumps(full_report, indent=2))
    else:
        print(json.dumps(findings_json, indent=2))
        print(f"\n================ SUMMARY ================")
        print(f"Files scanned: {result.scanned_files_count}")
        print(f"Files skipped: {result.skipped_files_count}")
        print(f"Total findings: {len(result.findings)}")
        if result.summary:
            print(f"Risk score: {result.summary.risk_score} ({result.summary.risk_category})")
            print(f"Critical: {result.summary.critical_count} | High: {result.summary.high_count} | Medium: {result.summary.medium_count}")
        print(f"Scan complete: {result.scan_complete}")
        if result.tool_errors:
            print(f"Errors encountered: {len(result.tool_errors)}")
        print(f"=========================================\n")


if __name__ == "__main__":
    main()
