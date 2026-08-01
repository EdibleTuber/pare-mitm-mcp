import re
from pare_mitm_mcp.daemon.store import FlowStore


def _flow(host="api.example.com", method="POST", status=200, body='{"tok":"abc"}', ts=1.0):
    return {
        "ts": ts, "kind": "flow", "method": method, "host": host, "path": "/v1/login",
        "scheme": "https", "status": status, "content_type": "application/json",
        "resp_size": len(body), "error": None,
        "req_headers": {"Host": host}, "req_body": "",
        "resp_headers": {"Content-Type": "application/json"}, "resp_body": body,
    }


def test_add_assigns_ids_and_summaries_newest_first():
    s = FlowStore()
    s.add(_flow(host="a.com", ts=1.0))
    s.add(_flow(host="b.com", ts=2.0))
    sums = s.summaries()
    assert [r["host"] for r in sums] == ["b.com", "a.com"]
    assert set(sums[0]) == set(FlowStore_summary_keys())
    assert "resp_body" not in sums[0]


def FlowStore_summary_keys():
    from pare_mitm_mcp.daemon.store import SUMMARY_KEYS
    return SUMMARY_KEYS


def test_ring_buffer_evicts_oldest():
    s = FlowStore(max_flows=2)
    s.add(_flow(host="a.com", ts=1.0))
    s.add(_flow(host="b.com", ts=2.0))
    s.add(_flow(host="c.com", ts=3.0))
    hosts = [r["host"] for r in s.summaries()]
    assert hosts == ["c.com", "b.com"]  # a evicted


def test_since_and_host_filter():
    s = FlowStore()
    s.add(_flow(host="a.com", ts=1.0))
    s.add(_flow(host="a.com", ts=5.0))
    s.add(_flow(host="b.com", ts=6.0))
    assert len(s.summaries(since=4.0)) == 2
    assert len(s.summaries(host="a.com")) == 2
    assert len(s.summaries(host="a.com", since=4.0)) == 1


def test_error_rows_counted_and_listed():
    s = FlowStore()
    s.add({"ts": 1.0, "kind": "error", "method": None, "host": "pin.example.com",
           "path": "", "scheme": "https", "status": None, "content_type": None,
           "resp_size": 0, "error": "TLS handshake failed",
           "req_headers": {}, "req_body": "", "resp_headers": {}, "resp_body": ""})
    assert s.health()["tls_errors"] == 1
    assert s.summaries()[0]["kind"] == "error"


def test_get_returns_full_record():
    s = FlowStore()
    fid = s.add(_flow(body='{"secret":"xyz"}'))
    rec = s.get(fid)
    assert rec["resp_body"] == '{"secret":"xyz"}'
    assert s.get("nope") is None


def test_search_scopes_and_snippet():
    s = FlowStore()
    s.add(_flow(host="api.example.com", body='{"token":"deadbeef"}'))
    hits = s.search("deadbeef", scope="resp-body")
    assert len(hits) == 1 and "deadbeef" in hits[0]["snippet"]
    assert s.search("deadbeef", scope="url") == []
    assert len(s.search("example.com", scope="url")) == 1
