import json
import os
import secrets

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.models import (
    GraphReviewEvent,
    GraphReviewRequest,
    GraphReviewReversalRequest,
    GraphReviewHistoryResponse,
    GraphReviewEvaluationExport,
    RingLookupResponse,
)
from app.services.fraud_graph import get_ring_info
from app.services.fraud_graph_reviews import (
    create_review,
    reverse_review,
    get_review_history,
    verify_review_history,
    export_evaluation_records,
)

router = APIRouter(prefix="/api/graph", tags=["Fraud Graph Agent"])

bearer_scheme = HTTPBearer(auto_error=False)


def require_graph_analyst(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> str:
    """
    Resolve a bearer token to an analyst identity using server configuration.

    FRAUD_GRAPH_ANALYST_TOKENS must contain a JSON mapping:
    {"long-random-token": "ANALYST-001"}

    Analyst identities are never accepted from request bodies.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Analyst authentication is required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    configured_tokens = os.getenv("FRAUD_GRAPH_ANALYST_TOKENS", "")

    if not configured_tokens:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Graph analyst authentication is not configured",
        )

    try:
        token_map = json.loads(configured_tokens)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Graph analyst authentication configuration is invalid",
        ) from exc

    if not isinstance(token_map, dict):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Graph analyst authentication configuration must be a JSON object",
        )

    valid_entries = [
        (token, analyst_id.strip())
        for token, analyst_id in token_map.items()
        if (
            isinstance(token, str)
            and len(token) >= 32
            and isinstance(analyst_id, str)
            and analyst_id.strip()
        )
    ]

    if not valid_entries:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No valid graph analyst credentials are configured",
        )

    supplied_token = credentials.credentials.encode("utf-8")
    matched_analyst = None

    for configured_token, analyst_id in valid_entries:
        if secrets.compare_digest(
            supplied_token,
            configured_token.encode("utf-8"),
        ):
            matched_analyst = analyst_id

    if matched_analyst is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid analyst credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return matched_analyst


@router.get("/ring/{account_id}", response_model=RingLookupResponse)
def ring_lookup(
    account_id: str,
    analyst_id: str = Depends(require_graph_analyst),
):
    return get_ring_info(account_id)


@router.post(
    "/edges/{edge_id}/reviews",
    response_model=GraphReviewEvent,
    status_code=status.HTTP_201_CREATED,
)
def submit_edge_review(
    edge_id: str,
    request: GraphReviewRequest,
    analyst_id: str = Depends(require_graph_analyst),
):
    try:
        return create_review(
            edge_id=edge_id,
            decision=request.decision,
            reason=request.reason,
            analyst_id=analyst_id,
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc.args[0]),
        ) from exc


@router.get(
    "/edges/{edge_id}/reviews",
    response_model=GraphReviewHistoryResponse,
)
def edge_review_history(
    edge_id: str,
    analyst_id: str = Depends(require_graph_analyst),
):
    try:
        return get_review_history(edge_id)
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc.args[0]),
        ) from exc


@router.post(
    "/edges/{edge_id}/reviews/{event_id}/reverse",
    response_model=GraphReviewEvent,
)
def reverse_edge_review(
    edge_id: str,
    event_id: str,
    request: GraphReviewReversalRequest,
    analyst_id: str = Depends(require_graph_analyst),
):
    try:
        return reverse_review(
            edge_id=edge_id,
            event_id=event_id,
            reason=request.reason,
            analyst_id=analyst_id,
        )
    except LookupError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc.args[0]),
        ) from exc


@router.get("/reviews/export", response_model=GraphReviewEvaluationExport)
def graph_review_evaluation_export(
    analyst_id: str = Depends(require_graph_analyst),
):
    return export_evaluation_records()


@router.get("/edges/{edge_id}/reviews/integrity")
def edge_review_integrity(
    edge_id: str,
    analyst_id: str = Depends(require_graph_analyst),
):
    try:
        return verify_review_history(edge_id)
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc.args[0]),
        ) from exc