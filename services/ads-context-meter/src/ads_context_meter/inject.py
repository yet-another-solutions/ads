"""Class-level Dishka inject for Litestar controllers."""

from __future__ import annotations

from collections.abc import Callable
from inspect import Parameter, signature
from typing import Any, get_type_hints

from dishka.integrations.base import default_parse_dependency
from dishka.integrations.litestar import inject as inject_handler
from litestar.handlers import HTTPRouteHandler
from litestar.types import Empty


def inject[T](cls: type[T]) -> type[T]:
    """Resolve ``FromDishka`` fields onto ``self`` for every HTTP handler."""
    if not isinstance(cls, type):
        raise TypeError("@inject must decorate a class")
    fields = {
        name: hint
        for name, hint in _own_type_hints(cls).items()
        if default_parse_dependency(Parameter(name, Parameter.KEYWORD_ONLY), hint) is not None
    }
    if not fields:
        return cls
    for value in vars(cls).values():
        if isinstance(value, HTTPRouteHandler):
            value._fn = inject_handler(_bind_fields(value._fn, fields))  # noqa: SLF001
            value._parsed_fn_signature = Empty  # noqa: SLF001
            value._parsed_return_field = Empty  # noqa: SLF001
            value._parsed_data_field = Empty  # noqa: SLF001
            value._signature_model = Empty  # noqa: SLF001
    return cls


def _own_type_hints(cls: type[Any]) -> dict[str, Any]:
    holder = type(
        f"_{cls.__name__}Hints",
        (),
        {
            "__annotations__": dict(getattr(cls, "__annotations__", {})),
            "__module__": cls.__module__,
        },
    )
    return get_type_hints(holder, include_extras=True)


def _bind_fields(func: Callable[..., Any], fields: dict[str, Any]) -> Callable[..., Any]:
    orig_sig = signature(func)
    params = list(orig_sig.parameters.values())
    existing = {param.name for param in params}
    extras = [
        Parameter(name, Parameter.KEYWORD_ONLY, annotation=hint)
        for name, hint in fields.items()
        if name not in existing
    ]
    field_names = tuple(name for name in fields if name not in existing)

    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        instance = args[0]
        for name in field_names:
            setattr(instance, name, kwargs.pop(name))
        return await func(*args, **kwargs)

    wrapper.__signature__ = orig_sig.replace(parameters=[*params, *extras])  # type: ignore[attr-defined]
    annotations = dict(getattr(func, "__annotations__", {}))
    annotations.update({name: fields[name] for name in field_names})
    wrapper.__annotations__ = annotations
    wrapper.__name__ = getattr(func, "__name__", "wrapper")
    wrapper.__qualname__ = getattr(func, "__qualname__", wrapper.__name__)
    wrapper.__module__ = getattr(func, "__module__", __name__)
    wrapper.__wrapped__ = func  # type: ignore[attr-defined]
    return wrapper
