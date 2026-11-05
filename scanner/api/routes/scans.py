from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from scanner.database.session import get_db
from scanner.services.scan_service import ScanService
from scanner.api.dependencies import rate_limit_dependency
from scanner.workers.scan_worker import ScanWorker
from scanner.messaging.kafka_producer import kafka_producer

router = APIRouter(prefix="/api/v1/scans", tags=["Scans"])


class ScanRequest(BaseModel):
    repository_url: str = Field(
        ...,
        description="Public GitHub repository URL (e.g. https://github.com/owner/repo)",
        examples=["https://github.com/owner/repo"],
    )


class ScanCreationResponse(BaseModel):
    scan_id: str
    status: str
    message: str


class ScanStatusResponse(BaseModel):
    scan_id: str
    repository_url: str
    repository_owner: str
    repository_name: str
    status: str
    created_at: str | None
    started_at: str | None
    completed_at: str | None
    error_message: str | None
    scan_version: str


class PaginatedScanHistoryResponse(BaseModel):
    page: int
    page_size: int
    total_scans: int
    items: list[ScanStatusResponse]


@router.post(
    "",
    response_model=ScanCreationResponse,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(rate_limit_dependency)],
)
def create_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks = None,
    db: Session = Depends(get_db),
):
    """Submit a GitHub repository URL for security scanning."""
    service = ScanService(db)
    try:
        job = service.create_scan(request.repository_url)
        if background_tasks is not None and not kafka_producer.producer:
            worker = ScanWorker()
            background_tasks.add_task(worker.process_scan_job, job.id, job.repository_url)
        return ScanCreationResponse(
            scan_id=job.id,
            status=job.status,
            message="Scan job accepted",
        )
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err),
        )


@router.get("/{scan_id}", response_model=ScanStatusResponse)
def get_scan_status(
    scan_id: str,
    db: Session = Depends(get_db),
):
    """Retrieve the status and timing metadata for a scan job."""
    service = ScanService(db)
    job = service.get_scan(scan_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan job '{scan_id}' not found",
        )

    return ScanStatusResponse(
        scan_id=job.id,
        repository_url=job.repository_url,
        repository_owner=job.repository_owner,
        repository_name=job.repository_name,
        status=job.status,
        created_at=job.created_at.isoformat() if job.created_at else None,
        started_at=job.started_at.isoformat() if job.started_at else None,
        completed_at=job.completed_at.isoformat() if job.completed_at else None,
        error_message=job.error_message,
        scan_version=job.scan_version,
    )


@router.post("/{scan_id}/cancel")
def cancel_scan(
    scan_id: str,
    db: Session = Depends(get_db),
):
    """Cancel a queued or eligible running scan job."""
    service = ScanService(db)
    success = service.cancel_scan(scan_id)
    if not success:
        job = service.get_scan(scan_id)
        if not job:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan job '{scan_id}' not found",
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scan job '{scan_id}' cannot be cancelled in state '{job.status}'",
        )

    return {
        "scan_id": scan_id,
        "status": "cancelled",
        "message": "Scan job cancelled successfully",
    }


@router.get("", response_model=PaginatedScanHistoryResponse)
def list_scans(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    """Retrieve paginated scan job history."""
    service = ScanService(db)
    jobs, total = service.list_scans(page=page, page_size=page_size)

    items = [
        ScanStatusResponse(
            scan_id=j.id,
            repository_url=j.repository_url,
            repository_owner=j.repository_owner,
            repository_name=j.repository_name,
            status=j.status,
            created_at=j.created_at.isoformat() if j.created_at else None,
            started_at=j.started_at.isoformat() if j.started_at else None,
            completed_at=j.completed_at.isoformat() if j.completed_at else None,
            error_message=j.error_message,
            scan_version=j.scan_version,
        )
        for j in jobs
    ]

    return PaginatedScanHistoryResponse(
        page=page,
        page_size=page_size,
        total_scans=total,
        items=items,
    )

