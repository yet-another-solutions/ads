"""Guard the explicit, temporary selected-service publication boundary."""

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
    assert set(inputs) == {"expected_sha", "service_selection"}
    assert inputs["expected_sha"]["required"] == "true"
    assert inputs["service_selection"] == {
        "description": "Publish only the reviewed affected services",
        "required": "true",
        "type": "choice",
        "default": "manager-egress",
        "options": ["manager-egress", "ipc"],
    }
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


def test_only_selected_complete_service_suites_run_before_push():
    jobs = workflow()["jobs"]
    assert set(jobs) == {"preflight", "service-tests", "publish-image", "summary"}
    tests = jobs["service-tests"]
    assert tests["needs"] == "preflight"
    assert tests["strategy"]["matrix"] == "${{ fromJSON(needs.preflight.outputs.matrix) }}"
    assert jobs["preflight"]["outputs"]["matrix"] == "${{ steps.identity.outputs.matrix }}"
    assert tests["env"]["PYTHONPATH"] == "libraries/ads-commons/tests"
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
    ipc_workflow = next(
        step
        for step in tests["steps"]
        if step.get("name") == "Scoped workflow tests for IPC selection"
    )
    assert ipc_workflow["if"] == "matrix.service == 'ads-sandbox-ipc'"
    assert ipc_workflow["run"] == "uv run --no-sync pytest deploy/tests/test_slice21_publish.py"


def test_publish_uses_selected_existing_platform_sets_no_latest_or_release():
    jobs = workflow()["jobs"]
    publish = jobs["publish-image"]
    assert publish["strategy"]["matrix"] == "${{ fromJSON(needs.preflight.outputs.matrix) }}"
    qemu = next(
        step for step in publish["steps"] if step.get("uses") == "docker/setup-qemu-action@v4"
    )
    assert qemu["if"] == "contains(matrix.platforms, 'linux/arm64')"
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
        "SERVICE_SELECTION": "manager-egress",
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


@pytest.mark.parametrize(
    ("selection", "expected"),
    [
        (
            "manager-egress",
            [
                {"service": "ads-sandbox-manager", "platforms": "linux/amd64,linux/arm64"},
                {"service": "ads-sandbox-egress", "platforms": "linux/amd64"},
            ],
        ),
        (
            "ipc",
            [
                {"service": "ads-sandbox-ipc", "platforms": "linux/amd64,linux/arm64"},
            ],
        ),
    ],
)
def test_preflight_confirms_only_selected_absent_tags_and_emits_exact_identity(
    preflight, monkeypatch, selection, expected
):
    code, calls, output = preflight
    monkeypatch.setenv("SERVICE_SELECTION", selection)
    exec(code, {})
    assert len(calls) == 2 * len(expected)
    for index, item in enumerate(expected):
        assert calls[index * 2 + 1].endswith(
            "/" + item["service"] + "/manifests/slice21-" + "a" * 40
        )
    assert output.read_text() == (
        "image_tag=slice21-"
        + "a" * 40
        + "\nowner=fixture\n"
        + "matrix="
        + json.dumps({"include": expected})
        + "\n"
    )


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("EXPECTED_SHA", "not-a-sha"),
        ("EXPECTED_SHA", "b" * 40),
        ("GITHUB_REF", "refs/heads/feature"),
        ("GITHUB_RUN_ATTEMPT", "2"),
        ("SERVICE_SELECTION", "ads"),
        ("SERVICE_SELECTION", "ipc,ads-sandbox-manager"),
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
@pytest.mark.parametrize("selection", ["manager-egress", "ipc"])
def test_preflight_never_treats_existing_or_inaccessible_tag_as_absent(
    preflight, monkeypatch, status, selection
):
    code, _, output = preflight
    monkeypatch.setenv("SERVICE_SELECTION", selection)
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


@pytest.mark.parametrize("selection", ["manager-egress", "ipc"])
@pytest.mark.parametrize("mismatch", [None, "extra", "missing", "sha", "tag", "run", "owner"])
def test_summary_requires_exact_selected_artifacts(monkeypatch, tmp_path, selection, mismatch):
    services = (
        ["ads-sandbox-ipc"] if selection == "ipc" else ["ads-sandbox-manager", "ads-sandbox-egress"]
    )
    step = workflow()["jobs"]["summary"]["steps"][-1]
    assert step["env"] == {
        "IMAGE_TAG": "${{ needs.preflight.outputs.image_tag }}",
        "SELECTED_MATRIX": "${{ needs.preflight.outputs.matrix }}",
        "OWNER": "${{ needs.preflight.outputs.owner }}",
    }
    for key, value in {
        "SELECTED_MATRIX": json.dumps({"include": [{"service": s} for s in services]}),
        "OWNER": "fixture",
        "IMAGE_TAG": "slice21-" + "a" * 40,
        "GITHUB_SHA": "a" * 40,
        "GITHUB_RUN_ID": "123",
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary"),
    }.items():
        monkeypatch.setenv(key, value)
    artifacts = services.copy()
    if mismatch == "extra":
        artifacts.append("ads")
    if mismatch == "missing":
        artifacts.pop()
    for service in artifacts:
        evidence = {
            "IMAGE": "ghcr.io/fixture/" + service,
            "IMAGE_TAG": "slice21-" + "a" * 40,
            "GITHUB_SHA": "a" * 40,
            "GITHUB_RUN_ID": "123",
            "DIGEST": "sha256:" + "b" * 64,
        }
        field = {
            "sha": "GITHUB_SHA",
            "tag": "IMAGE_TAG",
            "run": "GITHUB_RUN_ID",
            "owner": "IMAGE",
        }.get(mismatch)
        if field:
            evidence[field] = "wrong"
        directory = tmp_path / "images" / service
        directory.mkdir(parents=True)
        (directory / "image.json").write_text(json.dumps(evidence))
    monkeypatch.chdir(tmp_path)
    code = compile(step["run"].split("\n", 1)[1].rsplit("\nPY", 1)[0], str(WORKFLOW), "exec")
    if mismatch:
        with pytest.raises(AssertionError):
            exec(code, {})
        assert not (tmp_path / "summary").exists()
    else:
        exec(code, {})
        summary = (tmp_path / "summary").read_text()
        assert "not full workspace regression" in summary
        assert "does not close slice 21" in summary
        assert all("ghcr.io/fixture/" + service in summary for service in services)
