"""Integration test for the HTTP listener — spins up a real server on a
random port and uses urllib to hit it."""
import threading
import urllib.request
import urllib.error
from honeytoken import tokens
from honeytoken.registry import Registry
from honeytoken.listener import build_server, HoneyHandler


def _start_server(tmp_path, port=0):
    reg_path = tmp_path / "reg.json"
    reg = Registry(reg_path)
    t = tokens.mint_canary_url("http://127.0.0.1:0")
    reg.add_token(t)

    srv = build_server(str(reg_path), port=port)
    actual_port = srv.server_address[1]
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    return srv, actual_port, reg_path, t


def test_health_endpoint_returns_ok(tmp_path):
    srv, port, _, _ = _start_server(tmp_path)
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2) as r:
            assert r.status == 200
            assert r.read().strip() == b"ok"
    finally:
        srv.shutdown()


def test_canary_url_records_trigger(tmp_path):
    srv, port, reg_path, t = _start_server(tmp_path)
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/c/{t.token_id}", timeout=2) as r:
            assert r.status == 200
            # should be a tiny gif
            body = r.read()
            assert body.startswith(b"GIF89a")
        # registry should now have one event
        reg2 = Registry(reg_path)
        evts = reg2.events_for(t.token_id)
        assert len(evts) == 1
        assert evts[0].source_ip == "127.0.0.1"
    finally:
        srv.shutdown()


def test_unknown_path_returns_404(tmp_path):
    srv, port, _, _ = _start_server(tmp_path)
    try:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/random/path", timeout=2)
            assert False, "should have raised"
        except urllib.error.HTTPError as e:
            assert e.code == 404
    finally:
        srv.shutdown()


def test_canary_url_with_unknown_token_still_returns_pixel(tmp_path):
    """Don't leak which token IDs are real vs not — always respond identically."""
    srv, port, _, _ = _start_server(tmp_path)
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/c/totally_fake", timeout=2) as r:
            assert r.status == 200
            assert r.read().startswith(b"GIF89a")
    finally:
        srv.shutdown()
