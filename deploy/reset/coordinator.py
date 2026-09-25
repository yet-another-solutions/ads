"""Restartable credential-preserving fresh-schema reset state machine."""

from __future__ import annotations

from copy import deepcopy
from uuid import uuid4

from models import PAYLOAD, refresh_backup, restore_models, validate_models
from protected import PreservationError
from workloads import CONTROLLERS


class ResetCoordinator:
    def __init__(self, store, databases, workloads, api):
        self.store, self.databases, self.workloads, self.api = store, databases, workloads, api
        services = [db.target.service for db in databases]
        if len(set(services)) != len(services) or services.count("ads-preferences") != 1:
            raise PreservationError("unique reset targets including preferences required")
        if set(services) - {item["service"] for item in workloads.definitions}:
            raise PreservationError("every target requires an explicit writer workload")
        # Both distributed runtime controllers are mandatory fences even when
        # their databases are not reset. The ADS/engine writers are explicit too.
        if not {"ads", "ads-engine", "ads-preferences", *CONTROLLERS} <= {
            item["service"] for item in workloads.definitions
        }:
            raise PreservationError("all ADS writers and lifecycle controllers must be fenced")

    def _scope(self):
        return [
            {
                "service": db.target.service,
                "database": db.target.database,
                "owner": db.target.owner,
                "schema": db.target.schema,
            }
            for db in self.databases
        ]

    def _save(self, checkpoint):
        self.store.write("checkpoint", checkpoint)

    def run(self, *, new_cycle=False):
        with self.store.lock():
            try:
                checkpoint = self.store.read("checkpoint")
            except FileNotFoundError:
                checkpoint = None
            if checkpoint is not None and (
                checkpoint["scope"] != self._scope()
                or checkpoint["database_urls"] != [db.target.url for db in self.databases]
            ):
                raise PreservationError("reset target scope differs from external checkpoint")
            if new_cycle and checkpoint is not None and checkpoint["phase"] != "complete":
                raise PreservationError("unfinished reset must resume, not start another cycle")
            if checkpoint is None or new_cycle:
                checkpoint = {
                    "schema": "ads-reset-v1",
                    "cycle": str(uuid4()),
                    "scope": self._scope(),
                    "database_urls": [db.target.url for db in self.databases],
                    "phase": "discovered",
                    "workloads": self.workloads.snapshot(),
                    "databases": [db.inventory() for db in self.databases],
                    "reset": [],
                    "initialized": [],
                    "quarantine": True,
                }
                # Original desired replicas and scopes commit before scaling.
                self._save(checkpoint)
            if checkpoint["phase"] == "complete":
                return self.evidence(checkpoint)
            if checkpoint["phase"] == "discovered":
                self.workloads.pause(checkpoint["workloads"])
                preferences = next(
                    db for db in self.databases if db.target.service == "ads-preferences"
                )
                backup = refresh_backup(self.store, preferences.models())
                # Prove the protected delegated owner authorization can reach
                # the supported API before destructive SQL. The application
                # preferences writer is the only temporarily resumed workload.
                self.workloads.start_preferences(checkpoint["workloads"])
                for owner in {row["user_id"] for row in backup}:
                    existing = self.api.models(owner)
                    for row in (row for row in backup if row["user_id"] == owner):
                        found = [model for model in existing if model["id"] == row["id"]]
                        if found and {key: found[0][key] for key in PAYLOAD} != {
                            key: row[key] for key in PAYLOAD
                        }:
                            raise PreservationError(
                                "pre-reset owner model differs from full backup"
                            )
                self.workloads.pause(checkpoint["workloads"])
                current_models = preferences.models()
                if current_models and current_models != backup:
                    raise PreservationError("model configuration changed during preservation")
                associations = {
                    db.target.service: db.associations()
                    for db in self.databases
                    if db.target.service in CONTROLLERS
                }
                self.store.write("associations", associations)
                # Historical association absence is NOT deletion authority.
                # Controllers remain quarantined after every destructive reset,
                # including an already-empty DB after a previous reset.
                checkpoint["phase"] = "preserved"
                self._save(checkpoint)
            validate_models(self.store.read("models"))
            self.store.read("associations")
            if checkpoint["phase"] == "preserved":
                for db, captured in zip(self.databases, checkpoint["databases"], strict=True):
                    if not self.workloads.fenced(checkpoint["workloads"]):
                        raise PreservationError("writers escaped their reset fence")
                    if db.target.service not in checkpoint["reset"]:
                        db.reset(captured)
                        checkpoint["reset"].append(db.target.service)
                        self._save(checkpoint)
                    if db.target.service not in checkpoint["initialized"]:
                        db.initialize(captured)
                        checkpoint["initialized"].append(db.target.service)
                        self._save(checkpoint)
                checkpoint["phase"] = "restore"
                self._save(checkpoint)
            if checkpoint["phase"] == "restore":
                if not self.workloads.fenced(
                    checkpoint["workloads"],
                    except_services=frozenset({"ads-preferences"}),
                ):
                    raise PreservationError("dependent writers escaped restoration fence")
                self.workloads.start_preferences(checkpoint["workloads"])
                backup = validate_models(self.store.read("models"))
                mapping = restore_models(backup, self.api, invoke=True)
                # A second pass verifies regenerated-ID idempotency before
                # resumption. Secret auth and all full rows stay encrypted.
                if restore_models(backup, self.api, invoke=False) != mapping:
                    raise PreservationError(
                        "restoration identity changed between verification passes"
                    )
                checkpoint["mapping"] = mapping
                checkpoint["phase"] = "restored"
                self._save(checkpoint)
            if checkpoint["phase"] == "restored":
                if not self.workloads.fenced(
                    checkpoint["workloads"],
                    except_services=frozenset({"ads-preferences"}),
                ):
                    raise PreservationError("dependent writers escaped restoration fence")
                checkpoint["phase"] = "resuming"
                self._save(checkpoint)
            if checkpoint["phase"] == "resuming":
                self.workloads.resume(checkpoint["workloads"], quarantine=True)
                if not self.workloads.fenced(
                    checkpoint["workloads"],
                    except_services=frozenset(
                        item["service"]
                        for item in checkpoint["workloads"]["items"]
                        if item["service"] not in CONTROLLERS
                    ),
                ):
                    raise PreservationError("historical lifecycle controllers escaped quarantine")
                checkpoint["phase"] = "complete"
                self._save(checkpoint)
            return self.evidence(checkpoint)

    @staticmethod
    def evidence(checkpoint):
        return {
            "cycle": checkpoint["cycle"],
            "phase": checkpoint["phase"],
            "scope": deepcopy(checkpoint["scope"]),
            "restored_models": len(checkpoint.get("mapping", {})),
            "lifecycle_controllers_quarantined": checkpoint["quarantine"],
        }
