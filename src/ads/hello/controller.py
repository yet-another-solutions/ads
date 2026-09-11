from __future__ import annotations

from typing import Any

from dishka.integrations.litestar import FromDishka, inject
from litestar import Controller, Request, get, post
from litestar.response import Redirect, Template

from ads.hello.service import HelloService
from ads.identity import identity_from_session, security_context_from_identity


class HelloController(Controller):
    path = "/"

    @get("/")
    @inject
    async def hello_page(
        self,
        request: Request[Any, Any, Any],
        service: FromDishka[HelloService],
    ) -> Template | Redirect:
        identity = identity_from_session(request.session)
        if identity is None:
            return Redirect("/login")
        context = security_context_from_identity(identity)
        message = service.greet(security_context=context)
        flash = request.session.pop("flash", None)
        return Template(
            template_name="hello.html",
            context={"message": message, "flash": flash, "name": identity.name},
        )

    @post("/hello/press")
    @inject
    async def press_button(
        self,
        request: Request[Any, Any, Any],
        service: FromDishka[HelloService],
    ) -> Redirect:
        identity = identity_from_session(request.session)
        if identity is None:
            return Redirect("/login")
        context = security_context_from_identity(identity)
        request.session["flash"] = service.press_button(security_context=context)
        return Redirect("/")
