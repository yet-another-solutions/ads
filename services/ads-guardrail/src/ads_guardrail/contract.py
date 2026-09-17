from __future__ import annotations

import msgspec

from ads_policy.contract import ConversationId, Site


class Workspace(msgspec.Struct, frozen=True):
    project: str
    repo: str
    env: str
    workdir: str


class Opening(msgspec.Struct, frozen=True):
    bearer: str
    workspace: Workspace
    conversation: ConversationId = ""


class Application(msgspec.Struct, frozen=True):
    name: str
    key_sha256: str
    workspace: Workspace


class McpServer(msgspec.Struct, frozen=True):
    name: str
    url: str
    site: Site
