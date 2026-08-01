# pare-mitm-mcp

HTTPS-traffic MCP worker for PARE. Wraps an operator-launched `mitmweb`
daemon and gives the agent four read-only tools over the captured flows —
no direct access to the proxy process, no ability to modify or replay
traffic in this version. All tools are risk tier `low`.

## Tools

| Tool | What it does |
|------|-------------|
| `list_flows` | Lists captured HTTPS flows as summary rows (`id, ts, kind, method, host, path, scheme, status, content_type, resp_size, error`). Filterable by `host`, `method`, `status`, `since` (unix ts), `limit`. `kind="error"` rows (failed TLS/connection attempts, e.g. cert pinning) are surfaced, not hidden. |
| `get_flow` | Full detail for one flow id: request line + headers + body, response headers + body. JSON bodies are pretty-printed; binary bodies are summarised as `<binary N bytes>`. |
| `search_flows` | Regex/substring search across a scope (`url`, `headers`, `req-body`, `resp-body`, `all`); returns matching flow ids with a context snippet. Runs daemon-side. A malformed regex comes back as an error result, not an exception. |
| `capture_health` | Is the proxy reachable? Returns `{reachable, flows, tls_errors, last_flow_ts}`. Used to disambiguate an empty capture: daemon down vs. nothing-triggered-yet vs. pinning breaking the handshake (`tls_errors > 0`). |

Tools surface to the model as `mitm_*` when mounted into PARE (`mitm_list_flows`, `mitm_get_flow`, `mitm_search_flows`, `mitm_capture_health`).

If the daemon rejects a request (e.g. `search_flows` with a malformed regex,
or `list_flows` with a bad filter) or isn't reachable at all, `list_flows`/
`get_flow`/`search_flows` return a clean `{"error": true, "summary": ...}`
result instead of raising. `capture_health` handles the unreachable case
differently — it's not an error result, it's `{reachable: false, flows: 0,
tls_errors: 0, last_flow_ts: null}`, since "daemon down" is itself the
useful status.

## Daemon model

The worker is a thin MCP-side client; all capture state lives in a
separately-launched `mitmweb` process:

```
mitmweb -s daemon/addon.py \
  --listen-host 0.0.0.0   --listen-port 8080   \   # device traffic
  --web-host 127.0.0.1    --web-port 8081          # human UI
```

- **Split binds.** The proxy listener binds `0.0.0.0` so a phone/emulator on
  the LAN can reach it; the mitmweb UI and the worker's own control API bind
  `127.0.0.1` and are never exposed off-box. See the security note below —
  the proxy bind is the one that needs a firewall rule.
- **`daemon/addon.py`** is a mitmproxy addon that hooks `response`/`error` and
  writes a normalized flow record (or an error record, for TLS/connection
  failures) into an in-process `FlowStore`, and starts a small stdlib
  `ControlServer` (HTTP, localhost-only) that exposes `/health`, `/flows`,
  `/flow/<id>`, and `/search` — the routes the worker's `DaemonClient` calls.
- **In-memory ring buffer.** `daemon/store.py`'s `FlowStore` holds flows in a
  `deque(maxlen=PARE_MITM_MAX_FLOWS)`. Once the buffer is full, the oldest
  flow is evicted as each new one arrives — this ring-buffer cap *is* the
  retention policy. There is no on-disk flow log; nothing survives a daemon
  restart, and old flows (which may hold live tokens/cookies) roll off
  automatically rather than accumulating.
- **Lifecycle** is operator-driven via `pare-mitm-daemon`:
  - `pare-mitm-daemon up` — idempotent; launches `mitmweb` if not already
    listening, waits up to ~5s for the control API to answer, prints the
    three ports.
  - `pare-mitm-daemon status` — reports up/down and, if up, flow/tls-error
    counts.
  - `pare-mitm-daemon down` — v1 does not kill the process (mitmweb is
    operator-launched in its own session); it prints the `pkill` invocation
    to run manually.
  - The PARE-side `/mitm up` / `/mitm down` / `/mitm status` commands call
    into this same launcher; an unrecognized subcommand prints a usage
    message rather than doing anything.

## Security note

- **The proxy listener (`0.0.0.0:8080` by default) is an open forward
  proxy.** Anything that can reach that port on your LAN can proxy traffic
  through it. Scope it to the device's IP with a host firewall rule before
  pointing a device at it on anything other than an isolated lab network.

  `ufw` (add the allow rule *before* the deny — ufw matches in rule order):
  ```bash
  sudo ufw allow from 192.168.1.50 to any port 8080 proto tcp
  sudo ufw deny 8080/tcp
  ```

  `iptables` equivalent:
  ```bash
  sudo iptables -A INPUT -p tcp --dport 8080 -s 192.168.1.50 -j ACCEPT
  sudo iptables -A INPUT -p tcp --dport 8080 -j DROP
  ```

  Replace `192.168.1.50` with the actual device/emulator IP. The mitmweb UI
  (`8081`) and control API (`8788`) already bind `127.0.0.1` and are not
  reachable off-box, so they don't need a rule.

- **Never commit captures.** `.gitignore` already excludes `*.mitm`,
  `*.flows`, and `captures/` — flow captures can contain live tokens,
  session cookies, and credentials. This worker itself keeps captures
  in-memory only (see ring buffer, above) and writes nothing to disk on its
  own, but don't override that by exporting a `.mitm` file into the repo.

- **Bodies flow into PARE's context.** `get_flow` and `search_flows` return
  raw request/response bodies (JSON pretty-printed, binary summarised) to
  the model. That's fine while PARE's inference is local — the traffic
  never leaves the box. **Flag this explicitly before pointing PARE at a
  hosted/cloud model**: captured bodies (which may include auth tokens or
  PII from the target app) would then leave the machine as part of the
  model's context.

## Configuration

All configuration is through environment variables, read by both the
worker and the `pare-mitm-daemon` launcher (they must agree, since the
worker talks to the daemon over the control API):

| Variable | Default | Purpose |
|----------|---------|---------|
| `PARE_MITM_CONTROL_HOST` | `127.0.0.1` | Bind/connect host for the control API (health/flows/search). Localhost-only by design — the control API has no auth, so binding it to a non-loopback host prints a startup warning (it would expose captured traffic to anything that can reach it). |
| `PARE_MITM_CONTROL_PORT` | `8788` | Port for the control API. |
| `PARE_MITM_PROXY_PORT` | `8080` | Port mitmproxy listens on for device traffic (bound `0.0.0.0` — see security note). |
| `PARE_MITM_WEB_PORT` | `8081` | Port for the mitmweb human UI (bound `127.0.0.1`). |
| `PARE_MITM_MAX_FLOWS` | `5000` | Ring-buffer retention cap — the maximum number of flows held in memory before the oldest are evicted. |

## Installing into PARE

`pare-mitm-mcp`'s worker entry is already declared in PARE's `workers.yaml`
under `workers.mitm`, gated behind `enable_mitm` (env `PARE_ENABLE_MITM`) so
it isn't mounted by default. To bring it up:

```bash
# from PARE's own venv
/home/edible/Projects/PARE/.venv/bin/pip install -e ~/Projects/pare-mitm-mcp

# then, launching PARE:
PARE_ENABLE_MITM=1  # mounts the mitm_* tools

# and, from inside a PARE session, start the capture daemon:
/mitm up
```

`/mitm status` reports daemon state even when the worker isn't mounted (it
tells you to set `PARE_ENABLE_MITM=1` if it's off); once mounted, `/mitm
status` calls `capture_health` through the worker.

**mitmproxy is a hard dependency**, not optional — it's pinned in
`pyproject.toml` (`mitmproxy>=11.0.0`) and installs alongside the worker.
The `mitmweb` binary it ships must be resolvable on `PATH` in whatever
environment runs `pare-mitm-daemon up` (the same venv `pip install -e`
installs into), or `up` will fail with "mitmweb not found — is mitmproxy
installed in this env?".

## The pinning caveat

PARE has no visibility into how the device/emulator is configured — it
doesn't set the device's proxy settings, doesn't install the mitmproxy CA
cert, and doesn't run the operator's frida unpin. Those are all
operator-side setup steps that happen before this worker sees any traffic.

If the target app does TLS pinning and the operator hasn't applied a frida
unpin, you will see `capture_health` report `tls_errors > 0` and
`list_flows` return `kind="error"` rows instead of real traffic. That's the
signal to distinguish "pinning is blocking the handshake" from "the app
just hasn't made a request yet" (which shows `tls_errors == 0` and
`flows == 0`) — treat `tls_errors > 0` as "go apply the unpin," not as a
capture-layer bug.

## Running tests

Install dev dependencies:

```bash
pip install -e ".[dev]"
```

mitmproxy has a fairly deep dependency tree; if `pip install` fails with a
resolver error (e.g. `ResolutionTooDeep`) on an older pip, upgrade pip first
and install mitmproxy on its own before the dev extras:

```bash
pip install --upgrade pip
pip install "mitmproxy>=11.0.0"
pip install -e ".[dev]"
```

Run the full suite:

```bash
pytest
```

37 tests cover the contract/conformance, the `FlowStore` ring buffer and
search, the `ControlServer` HTTP routes, the mitmproxy `addon` (flow/error
→ record mapping), the `DaemonClient`, the four tool handlers (including
the error-envelope behavior on daemon rejections), and the
`pare-mitm-daemon` launcher (idempotent `up`, bind-split command
construction). No live device or running `mitmweb` process is required —
the daemon-side tests exercise a real `ControlServer` fixture directly.
