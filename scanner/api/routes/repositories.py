import json
from typing import Any
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from scanner.database.session import get_db
from scanner.database.repositories import RepositoryRepository, ScanJobRepository
from scanner.database.models import UserModel
from scanner.api.routes.auth import get_current_user
from scanner.repository.github import validate_and_parse_github_url

router = APIRouter(prefix="/repositories", tags=["Repositories"])


class RepositoryCreateRequest(BaseModel):
    repository_url: str = Field(..., description="GitHub repository URL")
    default_branch: str = "main"
    is_private: bool = False


class RepositoryResponse(BaseModel):
    id: str
    url: str
    owner: str
    name: str
    default_branch: str
    is_private: bool
    detected_languages: list[str] = []
    detected_frameworks: list[str] = []
    created_at: datetime
    updated_at: datetime


class RepositoryDetailResponse(RepositoryResponse):
    recent_scans: list[dict[str, Any]] = []


class PaginatedRepositoriesResponse(BaseModel):
    page: int
    page_size: int
    total_repositories: int
    items: list[RepositoryResponse]


@router.post("", response_model=RepositoryResponse, status_code=status.HTTP_201_CREATED)
def create_repository(
    request: RepositoryCreateRequest,
    current_user: UserModel | None = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        parsed = validate_and_parse_github_url(request.repository_url)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    repo_repo = RepositoryRepository(db)
    user_id = current_user.id if current_user else None

    repo = repo_repo.create_repository(
        url=parsed.url,
        owner=parsed.owner,
        name=parsed.name,
        user_id=user_id,
        default_branch=request.default_branch,
        is_private=request.is_private,
    )

    return RepositoryResponse(
        id=repo.id,
        url=repo.url,
        owner=repo.owner,
        name=repo.name,
        default_branch=repo.default_branch,
        is_private=repo.is_private,
        detected_languages=json.loads(repo.detected_languages or "[]"),
        detected_frameworks=json.loads(repo.detected_frameworks or "[]"),
        created_at=repo.created_at,
        updated_at=repo.updated_at,
    )


@router.get("", response_model=PaginatedRepositoriesResponse)
def list_repositories(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: UserModel | None = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    repo_repo = RepositoryRepository(db)
    user_id = current_user.id if current_user else None
    items, total = repo_repo.list_repositories(user_id=user_id, page=page, page_size=page_size)

    results = []
    for r in items:
        results.append(
            RepositoryResponse(
                id=r.id,
                url=r.url,
                owner=r.owner,
                name=r.name,
                default_branch=r.default_branch,
                is_private=r.is_private,
                detected_languages=json.loads(r.detected_languages or "[]"),
                detected_frameworks=json.loads(r.detected_frameworks or "[]"),
                created_at=r.created_at,
                updated_at=r.updated_at,
            )
        )

    return PaginatedRepositoriesResponse(
        page=page,
        page_size=page_size,
        total_repositories=total,
        items=results,
    )


@router.get("/{id}", response_model=RepositoryDetailResponse)
def get_repository_details(
    id: str,
    db: Session = Depends(get_db),
):
    repo_repo = RepositoryRepository(db)
    repo = repo_repo.get_by_id(id)
    if not repo:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Repository not found")

    job_repo = ScanJobRepository(db)
    scans, _ = job_repo.list_jobs(page=1, page_size=10, repository_id=repo.id)

    recent_scans = []
    for s in scans:
        recent_scans.append({
            "scan_id": s.id,
            "status": s.status,
            "created_at": s.created_at.isoformat(),
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "risk_score": s.summary.risk_score if s.summary else None,
            "risk_category": s.summary.risk_category if s.summary else None,
        })

    return RepositoryDetailResponse(
        id=repo.id,
        url=repo.url,
        owner=repo.owner,
        name=repo.name,
        default_branch=repo.default_branch,
        is_private=repo.is_private,
        detected_languages=json.loads(repo.detected_languages or "[]"),
        detected_frameworks=json.loads(repo.detected_frameworks or "[]"),
        created_at=repo.created_at,
        updated_at=repo.updated_at,
        recent_scans=recent_scans,
    )

