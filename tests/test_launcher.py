from pare_mitm_mcp.config import Config
from pare_mitm_mcp.daemon import launcher


def test_is_up_false_when_nothing_listening():
    cfg = Config(control_port=1)  # nothing on :1
    assert launcher.is_up(cfg) is False


def test_is_up_true_against_live_control(control):
    srv, _ = control
    # control fixture binds an ephemeral port; point a Config at it
    port = int(srv.url.rsplit(":", 1)[1])
    assert launcher.is_up(Config(control_port=port)) is True


def test_build_mitmweb_cmd_has_addon_and_ports():
    cfg = Config(proxy_port=8080, web_port=8081)
    cmd = launcher.build_mitmweb_cmd(cfg)
    assert cmd[0] == "mitmweb"
    assert "-s" in cmd and launcher.addon_path() in cmd
    assert "8080" in " ".join(cmd) and "8081" in " ".join(cmd)


def test_addon_path_exists():
    import os
    assert os.path.isfile(launcher.addon_path())


def test_up_is_idempotent_when_already_running(control, capsys):
    srv, _ = control
    port = int(srv.url.rsplit(":", 1)[1])
    rc = launcher.main(["up"], cfg=Config(control_port=port))
    assert rc == 0 and "already up" in capsys.readouterr().out.lower()
