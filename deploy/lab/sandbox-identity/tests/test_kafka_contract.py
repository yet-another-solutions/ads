"""Offline regression checks; live smoke scripts prove the actual authorities."""

import importlib.util
import io
import json
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("lab_kafka", Path(__file__).parents[1] / "kafka.py")
assert SPEC is not None and SPEC.loader is not None
KAFKA = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(KAFKA)


class KafkaContractTest(unittest.TestCase):
    def test_properties_reject_jaas_injection(self):
        for password in ('bad"password', "bad\\password", "bad\npassword", "bad\rpassword"):
            with self.subTest(password=password), self.assertRaises(AssertionError):
                KAFKA.properties("ads-sandbox-ipc", password)

    def test_properties_use_scoped_sasl_identity(self):
        result = KAFKA.properties("ads-sandbox-ipc", "fixture-only")
        self.assertIn("security.protocol=SASL_PLAINTEXT", result)
        self.assertIn('username="ads-sandbox-ipc"', result)
        self.assertNotIn('username="ads"', result)

    def test_broker_and_acl_contract(self):
        fixture = {
            "spec": {"template": {"spec": {
                "containers": [{"name": "kafka", "env": [
                    {"name": "KAFKA_LISTENER_SECURITY_PROTOCOL_MAP",
                     "value": "CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT,"
                              "PLAINTEXT_ADS:PLAINTEXT,SASL_PLAINTEXT:SASL_PLAINTEXT"},
                    {"name": "PRESERVE_ME", "value": "unchanged"},
                ]}],
                "volumes": [{"name": "creds", "secret": {
                    "items": [{"key": "kafka_jaas.conf", "path": "kafka_jaas.conf"}],
                }}],
            }}},
        }
        names = ("kafka-credentials",) + tuple(
            f"ads-sandbox-{component}-kafka-credentials" for component in ("mcp", "manager", "ipc")
        )
        credentials = dict.fromkeys(names, "fixture-only")
        with (
            patch.object(KAFKA.sys, "stdin", io.StringIO(json.dumps(credentials))),
            patch.object(KAFKA, "run", return_value=json.dumps(fixture)),
            patch.object(KAFKA, "patch") as patches,
            patch.object(KAFKA, "cli"),
            patch.object(KAFKA, "acl") as acls,
            patch.object(KAFKA, "save_statefulset"),
            patch("sys.stdout", new_callable=io.StringIO),
        ):
            KAFKA.main()
        broker = next(c.args[2] for c in patches.call_args_list if c.args[0] == "statefulset")
        env = {e["name"]: e["value"] for e in broker["spec"]["template"]["spec"]["containers"][0]["env"]}
        self.assertEqual(env["KAFKA_SUPER_USERS"], "User:ads")
        self.assertEqual(env["KAFKA_ALLOW_EVERYONE_IF_NO_ACL_FOUND"], "false")
        self.assertEqual(env["PRESERVE_ME"], "unchanged")
        self.assertIn("CONTROLLER:SASL_PLAINTEXT", env["KAFKA_LISTENER_SECURITY_PROTOCOL_MAP"])
        self.assertIn("PLAINTEXT_ADS:PLAINTEXT", env["KAFKA_LISTENER_SECURITY_PROTOCOL_MAP"])
        for call in acls.call_args_list:
            principal, operations = call.args
            resources = call.kwargs
            if "Create" in operations or "Delete" in operations:
                self.assertEqual(principal, "ads-sandbox-manager")
                self.assertEqual(resources["topics"], ("sandbox.req.", "sandbox.res."))
                self.assertTrue(resources["prefix"])
            if principal == "ANONYMOUS":
                self.assertFalse(resources.get("prefix"))
                self.assertLessEqual(set(resources.get("topics", ())),
                                     {"ads.engine.request", "ads.engine.output"})
                self.assertLessEqual(set(resources.get("groups", ())), {"ads", "ads-engine"})
            if principal == "ads-sandbox-ipc":
                self.assertNotIn("ads.sandbox.recover", resources.get("topics", ()))
                self.assertNotIn("ads.sandbox.idle", resources.get("topics", ()))
            self.assertNotIn("*", resources.get("topics", ()))
            self.assertNotIn("*", resources.get("groups", ()))
        self.assertIn("ads.sandbox.manager.barrier", KAFKA.STATIC)
        barrier_acls = [
            c for c in acls.call_args_list
            if "ads.sandbox.manager.barrier" in c.kwargs.get("topics", ())
        ]
        self.assertEqual(len(barrier_acls), 1)
        self.assertEqual(barrier_acls[0].args,
                         ("ads-sandbox-manager", ("Read", "Write", "Describe")))


if __name__ == "__main__":
    unittest.main()
