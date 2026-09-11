from __future__ import annotations

from typing import Any

from dishka.integrations.litestar import FromDishka, inject
from litestar import Request, get, post
from litestar.di import NamedDependency
from litestar.response import Redirect, Template

from ads.authenticated import AuthenticatedController
from ads.hello.service import HelloService
from ads.identity import Identity
from ads.security_context import SecurityContext


class HelloController(AuthenticatedController):
    path = "/"

    @get("/")
    @inject
    async def hello_page(
        self,
        request: Request[Any, Any, Any],
        service: FromDishka[HelloService],
        identity: NamedDependency[Identity],
        security_context: NamedDependency[SecurityContext],
    ) -> Template:
        message = service.greet(security_context=security_context)
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
        security_context: NamedDependency[SecurityContext],
    ) -> Redirect:
        request.session["flash"] = service.press_button(security_context=security_context)
        return Redirect("/")
