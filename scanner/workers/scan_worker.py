from datetime import datetime, timezone
from pathlib import Path
from sqlalchemy.orm import Session

from scanner.core.engine import SecurityEngine, ScanExecutionResult
from scanner.database.session import SessionLocal
from scanner.database.repositories import ScanJobRepository, FindingRepository, ScanSummaryRepository
from scanner.repository.clone import safe_clone_repository
from scanner.cache.redis_client import redis_client


class ScanWorker:
    def __init__(
        self,
        engine: SecurityEngine | None = None,
        db_factory=SessionLocal,
    ):
        self.engine = engine or SecurityEngine()
        self.db_factory = db_factory

    def process_scan_job(
        self,
        scan_id: str,
        repository_url: str,
        local_repo_override: Path | None = None,
    ) -> bool:
        """Process a scan job asynchronously from start to finish.
        
        Guarantees:
        - Idempotency: Duplicate events for already completed or cancelled scans are ignored.
        - Stepwise status transitions: queued -> cloning -> scanning -> processing -> completed / failed.
        - Safe cleanup of all temporary repository data.
        - Scan completeness and scanner failure tracking.
        """
        db: Session = self.db_factory()
        job_repo = ScanJobRepository(db)
        finding_repo = FindingRepository(db)
        summary_repo = ScanSummaryRepository(db)

        try:
            job = job_repo.get_job(scan_id)
            if not job:
                return False

            # Idempotency Protection: If job already completed or cancelled, do not re-scan
            if job.status in {"completed", "cancelled"}:
                return True

            # Mark scan started
            started_at = datetime.now(timezone.utc)
            job_repo.update_status(scan_id, status="cloning", started_at=started_at)
            redis_client.set(f"scan:{scan_id}:status", "cloning", ttl_seconds=3600)

            def run_scan_on_directory(target_path: Path):
                # Check for cancellation
                current_job = job_repo.get_job(scan_id)
                if current_job and current_job.status == "cancelled":
                    return

                # Scanning phase
                job_repo.update_status(scan_id, status="scanning")
                redis_client.set(f"scan:{scan_id}:status", "scanning", ttl_seconds=3600)

                exec_result: ScanExecutionResult = self.engine.execute_scan(
                    target_path,
                    run_external_tools=True,
                )

                # Check for cancellation before saving
                current_job = job_repo.get_job(scan_id)
                if current_job and current_job.status == "cancelled":
                    return

                # Processing & persistence phase
                job_repo.update_status(scan_id, status="processing")
                redis_client.set(f"scan:{scan_id}:status", "processing", ttl_seconds=3600)

                finding_repo.save_findings_for_scan(scan_id, exec_result.findings)
                if exec_result.summary:
                    summary_repo.save_summary(scan_id, exec_result.summary)

                # Completed
                completed_at = datetime.now(timezone.utc)
                job_repo.update_status(
                    scan_id,
                    status="completed",
                    completed_at=completed_at,
                )
                redis_client.set(f"scan:{scan_id}:status", "completed", ttl_seconds=3600)

            if local_repo_override:
                run_scan_on_directory(local_repo_override)
            else:
                with safe_clone_repository(repository_url) as cloned_dir:
                    run_scan_on_directory(cloned_dir)

            return True

        except Exception as exc:
            completed_at = datetime.now(timezone.utc)
            job_repo.update_status(
                scan_id,
                status="failed",
                error_message=str(exc),
                completed_at=completed_at,
            )
            redis_client.set(f"scan:{scan_id}:status", "failed", ttl_seconds=3600)
            return False
        finally:
            db.close()

