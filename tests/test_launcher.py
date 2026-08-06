import os
import stat
import sys

import pytest

import pare_mitm_mcp
from pare_mitm_mcp.config import Config
from pare_mitm_mcp.daemon import launcher


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
