from __future__ import annotations

import secrets
from typing import Any

import anyio.to_thread
import structlog
from litestar import Litestar, get, post
from litestar.connection import ASGIConnection
from litestar.exceptions import ClientException, NotAuthorizedException
from litestar.handlers import BaseRouteHandler

from ads_commons.injection_scanner import SCAN_PATH, ScanRequest, ScanResponse, TextVerdict
from ads_injection_scanner.classifier import InjectionClassifier, PromptGuardClassifier
from ads_injection_scanner.config import Settings

logger = structlog.get_logger("ads.injection_scanner")

BEARER_PREFIX = "Bearer "


def require_api_token(connection: ASGIConnection[Any, Any, Any, Any], _: BaseRouteHandler) -> None:
    expected = str(connection.app.state.api_token)
    header = connection.headers.get("authorization", "")
    if not header.startswith(BEARER_PREFIX):
        raise NotAuthorizedException(detail="bearer token required")
    if not secrets.compare_digest(header[len(BEARER_PREFIX) :], expected):
        raise NotAuthorizedException(detail="bearer token required")


def create_app(settings: Settings, classifier: InjectionClassifier | None = None) -> Litestar:
    loaded = classifier if classifier is not None else _classifier_from(settings)

    @post(SCAN_PATH, guards=[require_api_token], status_code=200)
    async def scan(data: ScanRequest) -> ScanResponse:
        _reject_oversized(data, settings)
        scores = await anyio.to_thread.run_sync(_scores_of, loaded, data.texts)
        verdicts = [
            TextVerdict(score=score, injection=score >= settings.injection_threshold)
            for score in scores
        ]
        found = [verdict.score for verdict in verdicts if verdict.injection]
        if found:
            logger.warning("prompt injection found", texts=len(verdicts), highest=max(found))
        return ScanResponse(verdicts=verdicts)

    @get("/health/live", sync_to_thread=False)
    def live() -> dict[str, str]:
        return {"status": "ok"}

    @get("/health/ready", sync_to_thread=False)
    def ready() -> dict[str, str]:
        return {"status": "ok"}

    app = Litestar(route_handlers=[scan, live, ready])
    app.state.api_token = settings.api_token
    return app


def _classifier_from(settings: Settings) -> PromptGuardClassifier:
    return PromptGuardClassifier.from_directory(
        settings.model_dir,
        window_tokens=settings.window_tokens,
        window_overlap_tokens=settings.window_overlap_tokens,
        malicious_label_index=settings.malicious_label_index,
    )


def _reject_oversized(request: ScanRequest, settings: Settings) -> None:
    if len(request.texts) > settings.max_texts_per_scan:
        raise ClientException(
            detail=f"at most {settings.max_texts_per_scan} texts per scan", status_code=413
        )
    if sum(len(text) for text in request.texts) > settings.max_characters_per_scan:
        raise ClientException(
            detail=f"at most {settings.max_characters_per_scan} characters per scan",
            status_code=413,
        )


def _scores_of(classifier: InjectionClassifier, texts: list[str]) -> list[float]:
    return [classifier.malicious_probability(text) if text.strip() else 0.0 for text in texts]
