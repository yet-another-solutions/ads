from __future__ import annotations

from ads_policy.config import GovernanceSettings
from ads_policy.normalize import branch_name, egress_host, within_workdir

WORKDIR = GovernanceSettings().workdir


def test_workdir_paths_are_inside() -> None:
    assert within_workdir(f"{WORKDIR}/src/app.py", WORKDIR)
    assert within_workdir(WORKDIR, WORKDIR)
    assert within_workdir("src/app.py", WORKDIR)


def test_traversal_and_home_paths_are_outside() -> None:
    assert not within_workdir(f"{WORKDIR}/../other/.env", WORKDIR)
    assert not within_workdir(f"{WORKDIR}/./../../root/.ssh/id_rsa", WORKDIR)
    assert not within_workdir("../../etc/passwd", WORKDIR)
    assert not within_workdir("~/.aws/credentials", WORKDIR)
    assert not within_workdir("", WORKDIR)


def test_sibling_prefix_is_not_inside() -> None:
    assert not within_workdir(f"{WORKDIR}-other/secret", WORKDIR)


def test_egress_host_ignores_port_userinfo_and_query() -> None:
    assert egress_host("https://mirror.interlab/simple") == "mirror.interlab"
    assert egress_host("mirror.interlab:443") == "mirror.interlab"
    assert egress_host("MIRROR.INTERLAB") == "mirror.interlab"
    assert egress_host("https://mirror.interlab@evil.example/") == "evil.example"
    assert egress_host("https://evil.example/?to=https://mirror.interlab") == "evil.example"


def test_branch_name_strips_refs_and_remotes() -> None:
    assert branch_name("main") == "main"
    assert branch_name("refs/heads/main") == "main"
    assert branch_name("origin/main") == "main"
    assert branch_name("refs/remotes/origin/main") == "main"
    assert branch_name("Main") == "main"
    assert branch_name("feature/governance") == "feature/governance"
