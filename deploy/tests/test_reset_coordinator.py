# ruff: noqa: F811
from __future__ import annotations

from copy import deepcopy
from uuid import uuid4

import pytest
from test_reset_database import ServiceApi, reset_db, seed  # noqa: F401
from test_reset_preservation import load, models, protected, rows, store  # noqa: F401

workloads_module = load("workloads")
coordinator = load("coordinator")


class Workloads:
    """Only the Kubernetes workload API boundary is faked."""

    def __init__(self):
        self.definitions = [
            {"service": name, "kind": "Deployment", "name": name}
            for name in (
                "ads",
                "ads-engine",
                "ads-preferences",
                "ads-sandbox-manager",
                "ads-sandbox-mcp",
            )
        ]
        self.replicas = {row["service"]: 1 for row in self.definitions}
        self.events = []
        self.fail_resume = False

    def snapshot(self):
        return {
            "namespace": "fixture",
            "namespace_uid": str(uuid4()),
            "items": [
                {
                    **item,
                    "uid": str(uuid4()),
                    "replicas": self.replicas[item["service"]],
                    "selector": {"service": item["service"]},
                }
                for item in self.definitions
            ],
        }

    def pause(self, captured):
        self.events.append("pause")
        self.replicas = {name: 0 for name in self.replicas}

    def fenced(self, captured, *, except_services=frozenset()):
        return all(value == 0 for key, value in self.replicas.items() if key not in except_services)

    def start_preferences(self, captured):
        self.events.append("preferences")
        self.replicas["ads-preferences"] = 1

    def resume(self, captured, *, quarantine):
        assert quarantine
        self.events.append("resume")
        for row in captured["items"]:
            if row["service"] not in workloads_module.CONTROLLERS:
                self.replicas[row["service"]] = row["replicas"]
        if self.fail_resume:
            self.fail_resume = False
            raise TimeoutError("lost workload resume reply")


def build(reset_db, store):
    workloads = Workloads()
    api = ServiceApi(reset_db.engine)
    flow = coordinator.ResetCoordinator(store, [reset_db], workloads, api)
    return flow, workloads, api


def test_repeated_coordinated_reset_preserves_models_and_quarantines_old_controllers(
    reset_db, store, rows
):
    seed(reset_db, rows)
    flow, workloads, api = build(reset_db, store)
    first = flow.run()
    assert first["phase"] == "complete" and first["restored_models"] == 1
    assert first["lifecycle_controllers_quarantined"]
    assert workloads.replicas["ads"] == 1 and workloads.replicas["ads-sandbox-manager"] == 0
    assert workloads.replicas["ads-sandbox-mcp"] == 0
    assert flow.run() == first
    second = flow.run(new_cycle=True)
    assert second["cycle"] != first["cycle"] and second["phase"] == "complete"
    assert len(reset_db.models()) == 1 and len(api.invoked) == 2
    assert reset_db.models()[0]["authentication"] == rows[0]["authentication"]
    assert store.read("associations") == {}


@pytest.mark.parametrize("fault", ["drop", "initialize", "restore", "resume"])
def test_interrupted_reset_resumes_without_losing_credentials_or_duplicating_models(
    reset_db,
    store,
    rows,
    fault,
):
    seed(reset_db, rows)
    flow, workloads, api = build(reset_db, store)
    if fault == "resume":
        workloads.fail_resume = True
    elif fault == "restore":
        original = api.create
        fired = False

        def lost(*args):
            nonlocal fired
            result = original(*args)
            if not fired:
                fired = True
                raise TimeoutError("lost API creation reply")
            return result

        api.create = lost
    else:
        name = "reset" if fault == "drop" else "initialize"
        original = getattr(reset_db, name)
        fired = False

        def lost(*args):
            nonlocal fired
            original(*args)
            if not fired:
                fired = True
                raise TimeoutError("lost committed database operation reply")

        setattr(reset_db, name, lost)
    with pytest.raises((TimeoutError, protected.PreservationError)):
        flow.run()
    assert store.read("models")[0]["authentication"] == rows[0]["authentication"]
    assert workloads.replicas["ads-sandbox-manager"] == 0
    if fault != "resume":
        assert workloads.replicas["ads"] == 0
    with pytest.raises(protected.PreservationError, match="unfinished"):
        flow.run(new_cycle=True)
    completed = flow.run()
    assert completed["phase"] == "complete" and len(reset_db.models()) == 1
    assert workloads.replicas["ads-sandbox-manager"] == 0


def test_empty_source_recovers_from_verified_nonempty_external_backup(reset_db, store, rows):
    models.refresh_backup(store, rows)
    flow, workloads, api = build(reset_db, store)
    completed = flow.run()
    assert completed["phase"] == "complete" and completed["restored_models"] == 1
    assert reset_db.models()[0]["authentication"] == rows[0]["authentication"]


def test_owner_auth_failure_blocks_before_destructive_sql(reset_db, store, rows):
    seed(reset_db, rows)
    flow, workloads, api = build(reset_db, store)
    original = deepcopy(reset_db.models())

    def refuse(owner):
        raise RuntimeError("wrong or expired owner authorization")

    api.models = refuse
    with pytest.raises(RuntimeError):
        flow.run()
    assert reset_db.models() == original
    assert store.read("checkpoint")["phase"] == "discovered"
    assert workloads.replicas["ads"] == workloads.replicas["ads-sandbox-manager"] == 0
