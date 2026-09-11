from __future__ import annotations

import structlog

from ads.method_security import require_role
from ads.security_context import SecurityContext

logger = structlog.get_logger("ads.hello")


class HelloService:
    def greet(self, security_context: SecurityContext) -> str:
        del security_context
        return "hello world"

    @require_role("user")
    def press_button(self, security_context: SecurityContext) -> str:
        del security_context
        logger.info("button was pressed")
        return "button was pressed"
