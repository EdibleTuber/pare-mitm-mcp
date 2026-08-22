import os
import stat
import subprocess
import sys

import pytest

import pare_mitm_mcp
from pare_mitm_mcp.config import Config
from pare_mitm_mcp.daemon import launcher


@pytest.fixture(autouse=True)
def _isolated_home(monkeypatch, tmp_path):
    # Config()'s state_dir default expands "~" against $HOME at instantiation
    # time. Isolate every test in this module from the real
    # ~/.local/state/pare-mitm, including the pre-existing tests above that
    # construct bare Config() / Config(control_port=...) instances.
    monkeypatch.setenv("HOME", str(tmp_path))


def _make_exe(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\necho fake mitmweb\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return str(path)


def test_is_up_false_when_nothing_listening():
    cfg = Config(control_port=1)  # nothing on :1
    assert launcher.is_up(cfg) is False


def test_is_up_true_against_live_control(control):
    srv, _ = control
    # control fixture binds an ephemeral port; point a Config at it
    port = int(srv.url.rsplit(":", 1)[1])
    assert launcher.is_up(Config(control_port=port)) is True


def test_build_mitmweb_cmd_has_addon_and_ports(monkeypatch, tmp_path):
    exe = _make_exe(tmp_path / "mitmweb")
    monkeypatch.setattr(launcher, "resolve_mitmweb", lambda cfg: exe)
    cfg = Config(proxy_port=8080, web_port=8081)
    cmd = launcher.build_mitmweb_cmd(cfg)
    assert cmd[0] == exe
    assert os.path.isabs(cmd[0])
    assert "-s" in cmd and launcher.addon_path() in cmd
    assert "8080" in " ".join(cmd) and "8081" in " ".join(cmd)


def test_build_mitmweb_cmd_keeps_bind_split(monkeypatch, tmp_path):
    exe = _make_exe(tmp_path / "mitmweb")
    monkeypatch.setattr(launcher, "resolve_mitmweb", lambda cfg: exe)
    cmd = launcher.build_mitmweb_cmd(Config())
    assert "--listen-host" in cmd and "0.0.0.0" in cmd
    assert "--web-host" in cmd and "127.0.0.1" in cmd
    li = cmd.index("--listen-host")
    assert cmd[li + 1] == "0.0.0.0"
    wi = cmd.index("--web-host")
    assert cmd[wi + 1] == "127.0.0.1"


def test_addon_path_exists():
    assert os.path.isfile(launcher.addon_path())


def test_up_is_idempotent_when_already_running(control, capsys):
    srv, _ = control
    port = int(srv.url.rsplit(":", 1)[1])
    rc = launcher.main(["up"], cfg=Config(control_port=port))
    assert rc == 0 and "already up" in capsys.readouterr().out.lower()


# ---- resolve_mitmweb precedence ----------------------------------------


def _blank_out_all_fallbacks(monkeypatch, tmp_path):
    """Point every non-explicit resolution source at empty/missing locations."""
    fake_interp_dir = tmp_path / "no-mitmweb-here" / "bin"
    fake_interp_dir.mkdir(parents=True)
    monkeypatch.setattr(sys, "executable", str(fake_interp_dir / "python"))
    monkeypatch.setattr(launcher.shutil, "which", lambda name: None)
    fake_pkg_file = tmp_path / "no-repo-here" / "src" / "pare_mitm_mcp" / "__init__.py"
    fake_pkg_file.parent.mkdir(parents=True)
    monkeypatch.setattr(pare_mitm_mcp, "__file__", str(fake_pkg_file))


def test_resolve_mitmweb_explicit_path_wins(monkeypatch, tmp_path):
    _blank_out_all_fallbacks(monkeypatch, tmp_path)
    explicit = _make_exe(tmp_path / "explicit" / "mitmweb")
    # also make a PATH candidate available, to prove explicit still wins
    which_exe = _make_exe(tmp_path / "on-path" / "mitmweb")
    monkeypatch.setattr(launcher.shutil, "which", lambda name: which_exe)
    cfg = Config(mitmweb_path=explicit)
    assert launcher.resolve_mitmweb(cfg) == explicit


def test_resolve_mitmweb_explicit_bad_path_raises(monkeypatch, tmp_path):
    _blank_out_all_fallbacks(monkeypatch, tmp_path)
    bad = str(tmp_path / "does-not-exist" / "mitmweb")
    cfg = Config(mitmweb_path=bad)
    with pytest.raises(FileNotFoundError):
        launcher.resolve_mitmweb(cfg)


def test_resolve_mitmweb_falls_back_to_interpreter_adjacent(monkeypatch, tmp_path):
    _blank_out_all_fallbacks(monkeypatch, tmp_path)
    interp_dir = tmp_path / "venv" / "bin"
    exe = _make_exe(interp_dir / "mitmweb")
    monkeypatch.setattr(sys, "executable", str(interp_dir / "python"))
    cfg = Config()
    assert launcher.resolve_mitmweb(cfg) == exe


def test_resolve_mitmweb_falls_back_to_which(monkeypatch, tmp_path):
    _blank_out_all_fallbacks(monkeypatch, tmp_path)
    exe = _make_exe(tmp_path / "somewhere-on-path" / "mitmweb")
    monkeypatch.setattr(launcher.shutil, "which", lambda name: exe if name == "mitmweb" else None)
    cfg = Config()
    assert launcher.resolve_mitmweb(cfg) == exe


def test_resolve_mitmweb_falls_back_to_sibling_venv(monkeypatch, tmp_path):
    _blank_out_all_fallbacks(monkeypatch, tmp_path)
    repo = tmp_path / "repo"
    pkg_file = repo / "src" / "pare_mitm_mcp" / "__init__.py"
    pkg_file.parent.mkdir(parents=True)
    pkg_file.write_text("")
    monkeypatch.setattr(pare_mitm_mcp, "__file__", str(pkg_file))
    exe = _make_exe(repo / ".venv" / "bin" / "mitmweb")
    cfg = Config()
    assert launcher.resolve_mitmweb(cfg) == exe


def test_resolve_mitmweb_returns_none_when_nothing_found(monkeypatch, tmp_path):
    _blank_out_all_fallbacks(monkeypatch, tmp_path)
    cfg = Config()
    assert launcher.resolve_mitmweb(cfg) is None


def test_up_reports_actionable_message_when_mitmweb_missing(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(launcher, "resolve_mitmweb", lambda cfg: None)
    cfg = Config(control_port=1)  # nothing listening -> is_up() False, proceeds to launch
    rc = launcher._up(cfg)
    assert rc == 2
    err = capsys.readouterr().err.lower()
    assert "mitmweb" in err
    assert "pare_mitm_mitmweb" in err


def test_up_reports_resolved_binary_path_on_success(monkeypatch, tmp_path, capsys):
    exe = _make_exe(tmp_path / "mitmweb")
    monkeypatch.setattr(launcher, "resolve_mitmweb", lambda cfg: exe)

    calls = {}

    def fake_popen(cmd, **kwargs):
        calls["cmd"] = cmd

        class _P:
            pass

        return _P()

    monkeypatch.setattr(launcher.subprocess, "Popen", fake_popen)
    # False until Popen has been "launched", then True — mirrors "not up yet,
    # comes up after we spawn it" without short-circuiting the "already up" check.
    monkeypatch.setattr(launcher, "is_up", lambda cfg: "cmd" in calls)
    cfg = Config()
    rc = launcher._up(cfg)
    assert rc == 0
    out = capsys.readouterr().out
    assert exe in out
    assert calls["cmd"][0] == exe


# ---- resolve_web_token / ui_url ----------------------------------------


def test_resolve_web_token_explicit_password_wins(tmp_path):
    cfg = Config(web_password="explicit-token", state_dir=str(tmp_path / "state"))
    assert launcher.resolve_web_token(cfg) == "explicit-token"
    # explicit path is a pure passthrough — no file should be written for it.
    assert not os.path.exists(tmp_path / "state" / "web_token")


def test_resolve_web_token_persisted_file_is_reused(tmp_path):
    state_dir = str(tmp_path / "state")
    cfg = Config(state_dir=state_dir)
    first = launcher.resolve_web_token(cfg)

    # A fresh Config pointed at the same state_dir (simulating a daemon
    # restart) must recover the same token, so the UI URL stays stable.
    second = launcher.resolve_web_token(Config(state_dir=state_dir))
    assert second == first


def test_resolve_web_token_generates_and_persists_with_mode_0600(tmp_path):
    state_dir = tmp_path / "state"
    cfg = Config(state_dir=str(state_dir))
    token = launcher.resolve_web_token(cfg)

    token_path = state_dir / "web_token"
    assert token_path.is_file()
    assert token_path.read_text().strip() == token
    mode = stat.S_IMODE(token_path.stat().st_mode)
    assert mode == 0o600


def test_resolve_web_token_degrades_gracefully_on_unwritable_state_dir(monkeypatch, tmp_path):
    state_dir = tmp_path / "unwritable-state"
    cfg = Config(state_dir=str(state_dir))

    def _boom(*a, **kw):
        raise OSError("permission denied (simulated)")

    monkeypatch.setattr(launcher.os, "makedirs", _boom)
    token = launcher.resolve_web_token(cfg)
    # still a usable hex token, just not persisted anywhere.
    assert isinstance(token, str) and len(token) == 32
    assert not state_dir.exists()


def test_build_mitmweb_cmd_includes_web_password_and_keeps_existing_flags(monkeypatch, tmp_path):
    exe = _make_exe(tmp_path / "mitmweb")
    monkeypatch.setattr(launcher, "resolve_mitmweb", lambda cfg: exe)
    cfg = Config(web_password="fixed-test-token", state_dir=str(tmp_path / "state"))
    cmd = launcher.build_mitmweb_cmd(cfg)
    assert "--set" in cmd and "web_password=fixed-test-token" in cmd
    assert "--listen-host" in cmd and "0.0.0.0" in cmd
    assert "--web-host" in cmd and "127.0.0.1" in cmd
    assert "-s" in cmd and launcher.addon_path() in cmd


def test_ui_url_composes_expected_url():
    cfg = Config(web_port=9999)
    assert launcher.ui_url(cfg, "abc123") == "http://127.0.0.1:9999/?token=abc123"


def test_up_already_up_prints_ui_url(control, capsys, tmp_path):
    srv, _ = control
    port = int(srv.url.rsplit(":", 1)[1])
    cfg = Config(control_port=port, web_password="already-up-token", state_dir=str(tmp_path / "state"))
    rc = launcher._up(cfg)
    assert rc == 0
    out = capsys.readouterr().out
    assert "already up" in out.lower()
    assert "already-up-token" in out
    assert "ui:" in out


def test_status_prints_ui_url_when_up(control, capsys, tmp_path):
    srv, _ = control
    port = int(srv.url.rsplit(":", 1)[1])
    cfg = Config(control_port=port, web_password="status-token", state_dir=str(tmp_path / "state"))
    rc = launcher._status(cfg)
    assert rc == 0
    out = capsys.readouterr().out
    assert "status-token" in out
    assert "ui:" in out


def test_up_timeout_message_includes_log_path(monkeypatch, tmp_path, capsys):
    exe = _make_exe(tmp_path / "mitmweb")
    monkeypatch.setattr(launcher, "resolve_mitmweb", lambda cfg: exe)
    monkeypatch.setattr(launcher.subprocess, "Popen", lambda cmd, **kw: object())
    monkeypatch.setattr(launcher, "is_up", lambda cfg: False)
    monkeypatch.setattr(launcher.time, "sleep", lambda s: None)
    state_dir = tmp_path / "state"
    cfg = Config(control_port=1, state_dir=str(state_dir))
    rc = launcher._up(cfg)
    assert rc == 1
    err = capsys.readouterr().err
    assert str(state_dir / "daemon.log") in err


def test_up_redirects_mitmweb_output_to_log_file_not_devnull(monkeypatch, tmp_path):
    exe = _make_exe(tmp_path / "mitmweb")
    monkeypatch.setattr(launcher, "resolve_mitmweb", lambda cfg: exe)

    calls = {}

    def fake_popen(cmd, **kwargs):
        calls["kwargs"] = kwargs

        class _P:
            pass

        return _P()

    monkeypatch.setattr(launcher.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(launcher, "is_up", lambda cfg: "kwargs" in calls)
    state_dir = tmp_path / "state"
    cfg = Config(control_port=1, state_dir=str(state_dir))
    launcher._up(cfg)
    assert calls["kwargs"]["stdout"] != subprocess.DEVNULL
    assert calls["kwargs"]["stderr"] != subprocess.DEVNULL
    assert (state_dir / "daemon.log").exists()
