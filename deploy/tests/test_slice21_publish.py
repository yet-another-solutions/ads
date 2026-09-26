"""Guard the explicit, temporary two-service publication boundary."""

import io
import json
from pathlib import Path
from urllib.error import HTTPError

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/publish-slice21.yml"


def workflow():
    # BaseLoader keeps YAML 1.1's "on" from becoming a boolean key.
    return yaml.load(WORKFLOW.read_text(), Loader=yaml.BaseLoader)


def test_scoped_publish_is_manual_sha_bound_and_never_replaces_full_workflows():
    value = workflow()
    assert set(value["on"]) == {"workflow_dispatch"}
    inputs = value["on"]["workflow_dispatch"]["inputs"]
    assert set(inputs) == {"expected_sha"} and inputs["expected_sha"]["required"] == "true"
    assert value["concurrency"]["cancel-in-progress"] == "false"
    preflight = value["jobs"]["preflight"]["steps"][0]["run"]
    for guard in (
        'sha != os.environ["EXPECTED_SHA"]',
        'os.environ["GITHUB_REF"] != "refs/heads/" + os.environ["DEFAULT_BRANCH"]',
        'os.environ["GITHUB_RUN_ATTEMPT"] != "1"',
        '"slice21-" + sha',
        "refusing to overwrite",
        "error.code != 404",
        '"MANIFEST_UNKNOWN", "NAME_UNKNOWN"',
    ):
        assert guard in preflight
    assert value["permissions"] == {"contents": "read", "packages": "read"}
    assert (ROOT / ".github/workflows/publish.yml").is_file()
    assert (ROOT / ".github/workflows/ci.yml").is_file()


def test_only_manager_and_egress_complete_service_suites_run_before_push():
    jobs = workflow()["jobs"]
    assert set(jobs) == {"preflight", "service-tests", "publish-image", "summary"}
    tests = jobs["service-tests"]
    assert tests["needs"] == "preflight"
    assert tests["strategy"]["matrix"]["service"] == [
        "ads-sandbox-manager",
        "ads-sandbox-egress",
    ]
    run = next(
        step["run"] for step in tests["steps"] if step.get("name", "").startswith("Scoped lint")
    )
    assert 'pytest "services/$SERVICE/tests"' in run
    assert "nox" not in run and " -k " not in run
    assert jobs["publish-image"]["needs"] == ["preflight", "service-tests"]
    assert jobs["summary"]["needs"] == ["preflight", "service-tests", "publish-image"]
    native = next(
        step for step in tests["steps"] if step.get("name", "").startswith("Provision real")
    )
    assert native["if"] == "matrix.service == 'ads-sandbox-egress'"
    for tool in ("nginx", "ADS_EGRESS_OPENSSL4_ROOT", "delv", "sha256sum --check"):
        assert tool in native["run"]


def test_publish_has_only_two_existing_platform_sets_no_latest_or_release():
    jobs = workflow()["jobs"]
    publish = jobs["publish-image"]
    assert publish["strategy"]["matrix"]["include"] == [
        {"service": "ads-sandbox-manager", "platforms": "linux/amd64,linux/arm64"},
        {"service": "ads-sandbox-egress", "platforms": "linux/amd64"},
    ]
    assert publish["permissions"] == {"contents": "read", "packages": "write"}
    build = next(
        step for step in publish["steps"] if step.get("uses") == "docker/build-push-action@v6"
    )["with"]
    assert build["file"] == "services/${{ matrix.service }}/Containerfile"
    assert build["push"] == "true"
    assert build["provenance"] == build["sbom"] == "true"
    assert "latest" not in build["tags"]
    assert "${{ needs.preflight.outputs.image_tag }}" in build["tags"]
    assert not any(job.get("permissions", {}).get("contents") == "write" for job in jobs.values())
    for job in jobs.values():
        for step in job["steps"]:
            if step.get("uses") == "actions/checkout@v7":
                assert step["with"]["ref"] == "${{ github.sha }}"


@pytest.fixture
def preflight(monkeypatch, tmp_path):
    values = {
        "EXPECTED_SHA": "a" * 40,
        "GITHUB_SHA": "a" * 40,
        "GITHUB_REF": "refs/heads/master",
        "DEFAULT_BRANCH": "master",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_REPOSITORY_OWNER": "Fixture",
        "GITHUB_ACTOR": "fixture",
        "GH_TOKEN": "fixture-not-a-secret",
        "GITHUB_OUTPUT": str(tmp_path / "output"),
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    calls = []

    def urlopen(request, timeout):
        calls.append(request.full_url)
        assert timeout == 20
        if "/token?" in request.full_url:
            assert request.full_url.startswith("https://ghcr.io/token?")
            return io.StringIO(json.dumps({"token": "fixture-registry-token"}))
        assert request.full_url.startswith("https://ghcr.io/v2/fixture/ads-sandbox-")
        raise HTTPError(
            request.full_url,
            404,
            "fixture",
            {},
            io.BytesIO(b'{"errors":[{"code":"MANIFEST_UNKNOWN"}]}'),
        )

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    code = compile(workflow()["jobs"]["preflight"]["steps"][0]["run"], str(WORKFLOW), "exec")
    return code, calls, Path(values["GITHUB_OUTPUT"])


def test_preflight_confirms_both_absent_tags_and_emits_exact_identity(preflight):
    code, calls, output = preflight
    exec(code, {})
    assert len(calls) == 4
    assert calls[1].endswith("/ads-sandbox-manager/manifests/slice21-" + "a" * 40)
    assert calls[3].endswith("/ads-sandbox-egress/manifests/slice21-" + "a" * 40)
    assert output.read_text() == "image_tag=slice21-" + "a" * 40 + "\nowner=fixture\n"


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("EXPECTED_SHA", "not-a-sha"),
        ("EXPECTED_SHA", "b" * 40),
        ("GITHUB_REF", "refs/heads/feature"),
        ("GITHUB_RUN_ATTEMPT", "2"),
    ],
)
def test_preflight_rejects_unbound_or_repeat_attempt_before_registry(
    preflight, monkeypatch, key, value
):
    code, calls, output = preflight
    monkeypatch.setenv(key, value)
    with pytest.raises(SystemExit):
        exec(code, {})
    assert not calls and not output.exists()


@pytest.mark.parametrize("status", [200, 401, 403, 500, "unproven-404"])
def test_preflight_never_treats_existing_or_inaccessible_tag_as_absent(
    preflight, monkeypatch, status
):
    code, _, output = preflight
    calls = []

    def urlopen(request, timeout):
        calls.append(request.full_url)
        if "/token?" in request.full_url:
            return io.StringIO(json.dumps({"token": "fixture-registry-token"}))
        if status == 200:
            return io.StringIO("{}")
        code = 404 if status == "unproven-404" else status
        raise HTTPError(request.full_url, code, "fixture", {}, io.BytesIO(b'{"errors":[]}'))

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    with pytest.raises((SystemExit, HTTPError)):
        exec(code, {})
    assert len(calls) == 2 and not output.exists()
