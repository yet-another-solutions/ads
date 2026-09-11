from __future__ import annotations

import structlog

from ads.method_security import require_role

logger = structlog.get_logger("ads.hello")


class HelloService:
    def greet(self) -> str:
        return "hello world"

    @require_role("user")
    def press_button(self) -> str:
        logger.info("button was pressed")
        return "button was pressed"
