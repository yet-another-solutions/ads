import os
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from ads_sandbox_egress import runtime


@pytest.mark.parametrize(
    "failure",
    [
        None,
        "runtime-directory",
        "control-tls",
        "native-tls",
        "kernel-boundary",
        "block-custody",
        "serve",
    ],
)
def test_fixed_startup_stage_preserves_failure_cleanup_and_secret_suppression(
    tmp_path, monkeypatch, capsys, failure
):
    sentinel = RuntimeError("secret-sentinel credential=do-not-log\nforged log")
    visits = []
    settings = SimpleNamespace(network=object(), devices=object())

    class ParentPath(type(tmp_path)):
        def lstat(self):
            info = super().lstat()
            return os.stat_result((*info[:4], 0, *info[5:]))

    def path(value):
        return ParentPath(tmp_path) if str(value) == "/run/ads-egress" else Path(value)

    def step(name):
        visits.append(name)
        if name == failure:
            raise sentinel

    def tls(*args):
        step("control-tls")
        return object(), object(), object()

    def library(*args):
        step("native-tls")
        return object()

    @contextmanager
    def custody(*args):
        step("block-custody")
        try:
            yield object()
        finally:
            visits.append("custody-closed")

    async def serve(*args):
        step("serve")

    monkeypatch.setattr(runtime, "load_settings", lambda: settings)
    monkeypatch.setattr(runtime.os, "getuid", lambda: 0)
    monkeypatch.setattr(runtime, "Path", path)
    monkeypatch.setattr(runtime.os, "chmod", lambda *args: step("runtime-directory"))
    monkeypatch.setattr(runtime, "tls_files", tls)
    monkeypatch.setattr(runtime, "TLSLibrary", library)
    monkeypatch.setattr(
        runtime,
        "KernelBoundary",
        lambda *_: SimpleNamespace(establish=lambda: step("kernel-boundary")),
    )
    monkeypatch.setattr(runtime, "mounted_custody", custody)
    monkeypatch.setattr(runtime, "serve", serve)
    for name in ("WRAPPING_KEY_B64", "TLS_CERT_PEM", "TLS_KEY_PEM"):
        monkeypatch.setenv(runtime.PREFIX + name, "secret-environment-sentinel")

    if failure:
        with pytest.raises(RuntimeError) as caught:
            runtime.main()
        assert caught.value is sentinel
    else:
        runtime.main()
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == (f"egress runtime stage failed: {failure}\n" if failure else "")
    assert "secret" not in output.err and "forged" not in output.err
    assert not list(tmp_path.iterdir())
    assert ("custody-closed" in visits) == (failure in (None, "serve"))
    for name in ("WRAPPING_KEY_B64", "TLS_CERT_PEM", "TLS_KEY_PEM"):
        assert runtime.PREFIX + name not in os.environ
