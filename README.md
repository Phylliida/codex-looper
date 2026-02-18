# Looper

Looper is a small Flask service that coordinates three actions as one operation:

1. Send a Zulip notification.
2. Stop existing `codex exec` processes.
3. Start one fresh detached `codex exec` run and stream its output to logs.

It is useful when you want a repeatable "announce + reset + launch" workflow instead of manually juggling shell sessions and stale background tasks.

## What Looper Is For

Looper is an orchestration layer around `codex exec`, not a scheduler with queues. It is designed for:

- Triggering a single fresh Codex run from HTTP.
- Keeping at most one active Codex task at a time.
- Auditing run lifecycle and command output in local log files.
- Broadcasting run starts to Zulip (stream or private messages).
- Re-running Codex with the same task prompt over and over.

Looper also has optional idle polling that can auto-start a fresh `codex exec` run after log inactivity.

## Intended Workflow (Repeat The Same Prompt)

The main Looper pattern is to repeatedly run **the same prompt text**. This is intentional: in practice, Codex often performs best on a fresh first-pass run, so Looper resets state and re-launches with the same instructions each time.

To make repeated runs converge instead of drift, keep a persistent task list in the target repo and include its path directly in the prompt.

Recommended prompt shape:

1. Point Codex to one canonical TODO/burndown file.
2. Tell it to pick next unfinished item(s) from that file.
3. Require it to update that same file with progress, failures, and next steps before finishing.
4. Repeat with the same prompt on the next Looper run.

Example prompt snippet:

```text
Work from crates/vcad-topology/docs/phase5-geometric-topology-consistency.md.
Pick the next incomplete task, implement and verify it, then update that same file
with what you changed, what failed, and what remains.
```

## How A Run Works

`POST /run` executes this sequence:

1. Validate auth token (if configured) and request payload.
2. Send the Zulip message via `send-zulip-dm.js`.
3. Find live `codex exec` PIDs and terminate them (`SIGTERM`, then `SIGKILL` fallback).
4. Spawn:
   - `codex --ask-for-approval never exec --sandbox workspace-write -C <workspace> "<prompt>"`
5. Return JSON with PID, command, log path, and process-kill details.

Concurrency guard:

- Only one `/run` request executes at a time.
- If a run is already in progress, Looper returns HTTP `409` with `busy: another run is in progress`.

## Requirements

- Python 3.10+ (tested with modern Python 3.x).
- `pip` and virtualenv support.
- Node.js runtime with global `fetch` (Node 18+ recommended) for Zulip helper script.
- `pgrep` available on `PATH`.
- A usable `codex` binary (auto-detected or explicitly configured).

Python dependencies:

- `Flask==3.1.0` (see `requirements.txt`).

## Codex Subrepo Setup And Build

Looper will try these local `codex` binaries before falling back to `PATH`:

1. `./codex/codex`
2. `./codex/codex-rs/target/release/codex`
3. `./codex/codex-rs/target/debug/codex`

If you want Looper to use a local source checkout, set up `codex` in `<looper-dir>/codex`.

### Option A: clone as a plain nested repo

```bash
cd /home/bepis/Documents/looper
git clone https://github.com/openai/codex.git codex
```

### Option B: track codex as a git submodule (recommended for pinned revisions)

```bash
cd /home/bepis/Documents/looper
git submodule add https://github.com/openai/codex.git codex
git submodule update --init --recursive
```

After cloning this repo elsewhere, initialize submodules with:

```bash
git submodule update --init --recursive
```

### Build codex from source

Build from the Rust workspace (`codex/codex-rs`):

```bash
cd /home/bepis/Documents/looper/codex/codex-rs

# Install Rust if needed:
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# Build optimized binary:
cargo build --release
```

Binary output:

- Release: `/home/bepis/Documents/looper/codex/codex-rs/target/release/codex`
- Debug: `/home/bepis/Documents/looper/codex/codex-rs/target/debug/codex`

You can let Looper auto-detect these paths, or set:

```bash
export CODEX_EXEC_BINARY=/home/bepis/Documents/looper/codex/codex-rs/target/release/codex
```

## Quick Start

```bash
cd /home/bepis/Documents/looper
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python server.py
```

Server defaults:

- Host: `0.0.0.0`
- Port: `3456`
- Log level: `DEBUG`
- Server log file: `<looper-dir>/logs/looper-server.log`

Health check:

```bash
curl -sS http://127.0.0.1:3456/health
```

## API

### `GET /health`

Response:

```json
{"ok": true}
```

### `POST /run`

Request JSON fields:

- `zulip_message` (required): message sent before any process management.
- `codex_prompt` (optional): prompt to execute. If omitted, Looper uses a built-in default prompt that points Codex at a specific burndown/TODO document.
- `prompt` (optional legacy alias): used when `codex_prompt` is absent.
- `workspace` (optional): working directory passed to `codex exec -C`.
- `codex_exec_binary` (optional): absolute/relative path or executable name override.
- `codex_exec_delay_seconds` (optional): delay before spawning Codex.
- `codex_exec_startup_check_seconds` (optional): wait time before startup health check.
- `zulip_script_path` (optional): path to Zulip helper script.

Special behavior:

- To send only Zulip and skip launching Codex, set `"codex_prompt": ""`.
- If `workspace` is omitted, Looper uses `/home/bepis/Documents/verifycad/VerusCAD/`.
- If `zulip_script_path` is omitted, Looper uses `<looper-dir>/send-zulip-dm.js`.
- Best results usually come from reusing the same `codex_prompt` across runs and having that prompt reference a persistent TODO file path.

Legacy delay compatibility:

- If `codex_exec_delay_seconds` is omitted, Looper also accepts:
  - `startup_delay_seconds`
  - `sidebar_delay_seconds`
  - `new_task_delay_seconds`
  - `prompt_send_delay_seconds`
- These are summed into one effective spawn delay.

Example:

```bash
curl -sS -X POST http://127.0.0.1:3456/run \
  -H 'Content-Type: application/json' \
  -d '{
    "zulip_message":"Looper trigger: starting fresh run",
    "workspace":"/home/bepis/Documents/verifycad/VerusCAD",
    "codex_prompt":"Please continue the current verification task."
  }'
```

When `LOOPER_API_TOKEN` is set:

```bash
curl -sS -X POST http://127.0.0.1:3456/run \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer YOUR_TOKEN' \
  -d '{"zulip_message":"authorized trigger"}'
```

Typical success response fields:

- `ok`
- `zulip_output`
- `killed_codex_exec_pids`
- `remaining_codex_exec_pids`
- `workspace`
- `codex_exec_binary`
- `codex_exec_binary_source`
- `codex_exec_started`
- `codex_exec_result` (includes PID, command, log path)

## Logging

This is where logs go by default:

- Server/application logs: `<looper-dir>/logs/looper-server.log`
- Per-run Codex output logs: `<looper-dir>/logs/codex-exec-<YYYYMMDD-HHMMSS>-<request_id>.log`

`looper-server.log` includes:

- Request lifecycle events (`http.start`, `http.end`) with request IDs.
- Step-level run events (`run.step`, `run.success`, `run.fail`).
- Shell command telemetry (`cmd.start`, `cmd.done`, `cmd.fail`) with return code and trimmed output.
- Autopoll activity (`codex.exec.autopoll.*`).
- Mirrored raw Codex stdout/stderr lines (plain text, no log prefix) via the codex output logger.

Each `codex-exec-*.log` includes:

- Header lines with request ID, workspace, and full command.
- Raw combined stdout/stderr from the spawned `codex exec`.
- Final trailer line: `# codex_exec_return_code=<n>`.

Important log behavior:

- Log files are append-only.
- Log directory is created automatically.
- Looper does not implement log rotation or retention pruning.

Useful commands:

```bash
tail -f logs/looper-server.log
```

```bash
ls -1t logs/codex-exec-*.log | head
```

## Configuration

### Looper environment variables

- `LOOPER_HOST`: bind address (`0.0.0.0` default).
- `LOOPER_PORT`: port (`3456` default).
- `LOOPER_API_TOKEN`: if set, `/run` requires bearer token or `X-Looper-Token`.
- `LOOPER_LOG_LEVEL`: Python log level (`DEBUG` default).
- `LOOPER_SERVER_LOG_PATH`: server log path (`<looper-dir>/logs/looper-server.log` default).
- `CODEX_EXEC_BINARY`: preferred codex executable path/name.
- `CODEX_EXEC_DELAY_SECONDS`: default spawn delay (`1` default).
- `CODEX_EXEC_STARTUP_CHECK_SECONDS`: startup check wait (`1` default).
- `CODEX_EXEC_LOG_DIR`: directory for per-run logs (`<looper-dir>/logs` default).
- `LOOPER_AUTO_START_WHEN_IDLE`: enable idle polling/auto-start (`1` default; disable with `0`, `false`, `no`, `off`).
- `LOOPER_IDLE_POLL_SECONDS`: polling interval in seconds (`300` default).
- `LOOPER_IDLE_LOG_STALE_SECONDS`: required inactivity window for `codex-exec-*.log` mtime before autopoll starts a run (`600` default = 10 minutes).

Codex binary resolution order:

1. Request field `codex_exec_binary`.
2. Env var `CODEX_EXEC_BINARY`.
3. Local candidates:
   - `./codex/codex`
   - `./codex/codex-rs/target/release/codex`
   - `./codex/codex-rs/target/debug/codex`
4. `codex` from `PATH`.

### Zulip environment variables

Used by `send-zulip-dm.js`.

Credential sources:

- `ZULIPRC_PATH` and `ZULIP_PROFILE` (defaults: `~/.zuliprc`, profile `api`), or
- Direct env values:
  - `ZULIP_SITE`
  - `ZULIP_BOT_EMAIL`
  - `ZULIP_BOT_API_KEY`

Routing:

- `ZULIP_MESSAGE_TYPE`: `stream` (default) or `private`.
- `ZULIP_STREAM`: default stream for `stream` mode (`coding`).
- `ZULIP_TOPIC`: default topic for `stream` mode (`verified-cad`).
- `ZULIP_TO`: recipient for `private` mode (default `8-Tessa`).

Dry-run credential check:

```bash
node send-zulip-dm.js --dry-run
```

## Autopoll (Optional Background Auto-Start Mode)

If `LOOPER_AUTO_START_WHEN_IDLE=1`, a background thread runs every `LOOPER_IDLE_POLL_SECONDS`:

1. If `/run` is currently executing, skip this tick.
2. If any live `codex exec` process exists, skip this tick.
3. If `codex-exec-*.log` has been modified within the last `LOOPER_IDLE_LOG_STALE_SECONDS`, skip this tick.
4. Otherwise, start a new `codex exec` using default workspace and default prompt.

Autopoll uses log-file inactivity as a safety gate to reduce duplicate starts when process detection is noisy.
If no `codex-exec-*.log` files exist yet, autopoll treats that as inactive and is allowed to start.

Autopoll request IDs are prefixed with `auto` (for example `auto5f9ed4b2`).

## Shutdown Behavior

On server shutdown (`Ctrl-C`, normal process exit), Looper:

1. Stops autopoll loop.
2. Attempts to terminate tracked Codex child processes.

## Troubleshooting

- `401 unauthorized` on `/run`: set the right bearer token or unset `LOOPER_API_TOKEN`.
- `500 ... required tool is missing from PATH`: install missing tool (`node`, `pgrep`, or codex binary).
- `500 ... workspace is not a directory`: fix `workspace` in request body.
- Codex exits immediately: open `codex-exec-*.log` and inspect tail plus `# codex_exec_return_code`.
- Zulip send failures: run `node send-zulip-dm.js --dry-run` and verify Zulip credentials/env.

## Wrapper Usage

If you have an external wrapper script, point it at Looper's `/run` endpoint.

Example from a parent repo:

```bash
cd /home/bepis/Documents/verifycad/VerusCAD
./scripts/run-codex-task.sh "Looper trigger from wrapper"
```
