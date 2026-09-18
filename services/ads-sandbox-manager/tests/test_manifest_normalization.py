from copy import deepcopy

import pytest

from ads_sandbox_manager.sessions import contains


def manifest(**fields):
    return {"spec": {"template": {"spec": fields}}}


@pytest.mark.parametrize("field", ["tolerations", "imagePullSecrets"])
@pytest.mark.parametrize("actual", [{}, None, []])
def test_only_optional_empty_pod_lists_accept_api_omission(field, actual):
    expected = manifest(**{field: []})
    observed = manifest() if actual == {} else manifest(**{field: actual})
    assert contains(observed, expected)


@pytest.mark.parametrize("field", ["tolerations", "imagePullSecrets"])
def test_optional_nonempty_policy_cannot_be_lost_or_injected(field):
    empty = manifest(**{field: []})
    policy = manifest(**{field: [{"name": "required", "key": "required"}]})
    assert not contains(manifest(), policy)
    assert not contains(manifest(**{field: None}), policy)
    assert not contains(empty, policy)
    assert not contains(policy, empty)


@pytest.mark.parametrize("field", ["containers", "volumes", "capabilities", "env"])
def test_other_empty_fields_are_not_optional(field):
    assert not contains(manifest(), manifest(**{field: []}))
    assert not contains(manifest(**{field: None}), manifest(**{field: []}))


def test_normalization_does_not_ignore_missing_security_or_change_inputs():
    expected = manifest(tolerations=[], imagePullSecrets=[], hostNetwork=False)
    observed = manifest(hostNetwork=False)
    before = deepcopy(observed)
    assert contains(observed, expected)
    assert observed == before
    assert not contains(manifest(hostNetwork=True), expected)
    assert not contains(manifest(), expected)
    assert not contains({}, {"tolerations": []})
    assert not contains({}, {"required": None})
