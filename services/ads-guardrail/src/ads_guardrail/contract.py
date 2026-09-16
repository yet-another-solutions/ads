from __future__ import annotations

import msgspec

from ads_policy.contract import Placement


class Sandbox(msgspec.Struct, frozen=True):
    """Where an agent's task runs, as told by whoever put it there.

    This service stands outside every sandbox, so it cannot see one. The component
    that created the pod can: it chose the runtime class and knows the node it landed
    on. It sends that here, and the policy service derives the isolation level from it.
    Nothing has a default — a guessed placement would decide under the wrong rules.
    """

    project: str
    repo: str
    env: str
    workdir: str
    placement: Placement
    runtime_class_name: str | None = None
    node_labels: dict[str, str] = msgspec.field(default_factory=dict)


class Opening(msgspec.Struct, frozen=True):
    """A run to open for a person: their token, and where the task runs.

    The person is read from the token, once it is verified, and never taken from the
    caller's say-so. The run is theirs, not the token's: a refreshed token of the same
    person reaches the same run.
    """

    bearer: str
    sandbox: Sandbox


class Application(msgspec.Struct, frozen=True):
    """An application that calls with its own key and acts for no person — hermes.

    Nothing in its path knows the guardrail is there, so nothing would open a run for
    it. This service does, on its first call and again whenever the last run has
    ended. What is configured is the key's fingerprint, never the key; and where the
    application runs is stated by whoever deployed it, the same as for any sandbox.
    """

    name: str
    key_sha256: str
    sandbox: Sandbox
