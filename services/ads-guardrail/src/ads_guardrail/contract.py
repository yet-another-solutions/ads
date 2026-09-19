from __future__ import annotations

import msgspec

from ads_policy.contract import ConversationId, PolicyDecision, Site


class Workspace(msgspec.Struct, frozen=True):
    project: str
    repo: str
    env: str
    workdir: str


class Opening(msgspec.Struct, frozen=True):
    bearer: str
    workspace: Workspace
    conversation: ConversationId = ""


class Prompt(msgspec.Struct, frozen=True):
    run_id: str
    texts: tuple[str, ...]


class PromptReading(msgspec.Struct, frozen=True):
    decision: PolicyDecision
    texts: tuple[str, ...]
    withheld: bool = False


class Application(msgspec.Struct, frozen=True):
    name: str
    key_sha256: str
    workspace: Workspace


class McpServer(msgspec.Struct, frozen=True):
    name: str
    url: str
    site: Site
