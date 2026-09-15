from __future__ import annotations

from typing import Any

from litestar import Request, Response
from litestar.types import ExceptionHandlersMap

from ads_commons.security import AccessDenied, AuthenticationRequired


class ModelNotFound(Exception):
    """No model matches both id and the bound user."""

    def __init__(self, detail: str = "not found") -> None:
        super().__init__(detail)
        self.detail = detail


class InvalidModel(Exception):
    """Request body failed a non-msgspec catalog rule."""

    def __init__(self, detail: str = "invalid model") -> None:
        super().__init__(detail)
        self.detail = detail


def handle_authentication_required(
    request: Request[Any, Any, Any], exc: Exception
) -> Response[Any]:
    del request
    detail = exc.detail if isinstance(exc, AuthenticationRequired) else "authentication required"
    return Response(content={"status_code": 401, "detail": detail}, status_code=401)


def handle_access_denied(request: Request[Any, Any, Any], exc: Exception) -> Response[Any]:
    del request
    detail = exc.detail if isinstance(exc, AccessDenied) else "access denied"
    return Response(content={"status_code": 403, "detail": detail}, status_code=403)


def handle_model_not_found(request: Request[Any, Any, Any], exc: Exception) -> Response[Any]:
    del request
    detail = exc.detail if isinstance(exc, ModelNotFound) else "not found"
    return Response(content={"status_code": 404, "detail": detail}, status_code=404)


def handle_invalid_model(request: Request[Any, Any, Any], exc: Exception) -> Response[Any]:
    del request
    detail = exc.detail if isinstance(exc, InvalidModel) else "invalid model"
    return Response(content={"status_code": 400, "detail": detail}, status_code=400)


EXCEPTION_HANDLERS: ExceptionHandlersMap = {
    AuthenticationRequired: handle_authentication_required,
    AccessDenied: handle_access_denied,
    ModelNotFound: handle_model_not_found,
    InvalidModel: handle_invalid_model,
}
