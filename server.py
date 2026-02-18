#!/usr/bin/env python3
from __future__ import annotations

import atexit
import logging
import os
import shlex
import shutil
import signal
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from flask import Flask, g, jsonify, request

app = Flask(__name__)
RUN_LOCK = threading.Lock()
ACTIVE_CODEX_EXEC_PIDS_LOCK = threading.Lock()
ACTIVE_CODEX_EXEC_PIDS: set[int] = set()
AUTO_POLL_STOP_EVENT = threading.Event()

REPO_ROOT = Path(__file__).resolve().parent.parent
LOOPER_DIR = Path(__file__).resolve().parent
DEFAULT_WORKSPACE = "/home/bepis/Documents/verifycad/VerusCAD/"
DEFAULT_ZULIP_DM_SCRIPT = str(LOOPER_DIR / "send-zulip-dm.js")
DEFAULT_CODEX_EXEC_BINARY = os.getenv("CODEX_EXEC_BINARY", "").strip()
DEFAULT_CODEX_EXEC_DELAY_SECONDS = float(os.getenv("CODEX_EXEC_DELAY_SECONDS", os.getenv("PROMPT_SEND_DELAY_SECONDS", "1")))
DEFAULT_CODEX_EXEC_STARTUP_CHECK_SECONDS = float(os.getenv("CODEX_EXEC_STARTUP_CHECK_SECONDS", "1"))
DEFAULT_CODEX_EXEC_LOG_DIR = Path(
    os.getenv("CODEX_EXEC_LOG_DIR", str(LOOPER_DIR / "logs"))
)
DEFAULT_AUTO_START_WHEN_IDLE = os.getenv("LOOPER_AUTO_START_WHEN_IDLE", "1").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
DEFAULT_IDLE_POLL_SECONDS = float(os.getenv("LOOPER_IDLE_POLL_SECONDS", "300"))
DEFAULT_IDLE_LOG_STALE_SECONDS = float(os.getenv("LOOPER_IDLE_LOG_STALE_SECONDS", "600"))
DEFAULT_SERVER_LOG_PATH = Path(
    os.getenv("LOOPER_SERVER_LOG_PATH", str(DEFAULT_CODEX_EXEC_LOG_DIR / "looper-server.log"))
)
LOCAL_CODEX_EXEC_CANDIDATES = (
    LOOPER_DIR / "codex" / "codex",
    LOOPER_DIR / "codex" / "codex-rs" / "target" / "release" / "codex",
    LOOPER_DIR / "codex" / "codex-rs" / "target" / "debug" / "codex",
)
ENFORCED_CODEX_APPROVAL_POLICY = "never"
ENFORCED_CODEX_EXEC_SANDBOX = "workspace-write"
DEFAULT_CODEX_PROMPT = 'Pick a task in crates/vcad-topology/docs/phase5-geometric-topology-consistency.md and work through the burndown. Remember, the goal is to fully verify all code in vcad-topology. If you want to add extra things to do as well, or want to clean up the code in vcad-topology, feel free. Once you are finished, update that document with anything you did (even failed attempts are important to document to reduce repeated work). Note: Additional permissions for new commands cannot be granted, so work with what you have. At the very end, add and commit any changes, update scripts/run-codex-task.message.txt with a one sentence summary message, then run ./scripts/run-codex-task.sh.'
DEFAULT_LOG_LEVEL = os.getenv("LOOPER_LOG_LEVEL", "DEBUG").upper()

DEFAULT_CODEX_EXEC_LOG_DIR.mkdir(parents=True, exist_ok=True)
DEFAULT_SERVER_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=getattr(logging, DEFAULT_LOG_LEVEL, logging.DEBUG),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(DEFAULT_SERVER_LOG_PATH, mode="a", encoding="utf-8"),
    ],
    force=True,
)
LOGGER = logging.getLogger("looper")
CODEX_OUTPUT_LOGGER = logging.getLogger("looper.codex-output")
CODEX_OUTPUT_LOGGER.setLevel(getattr(logging, DEFAULT_LOG_LEVEL, logging.DEBUG))
CODEX_OUTPUT_LOGGER.propagate = False

_codex_output_stream_handler = logging.StreamHandler()
_codex_output_stream_handler.setFormatter(logging.Formatter("%(message)s"))
CODEX_OUTPUT_LOGGER.addHandler(_codex_output_stream_handler)

_codex_output_file_handler = logging.FileHandler(DEFAULT_SERVER_LOG_PATH, mode="a", encoding="utf-8")
_codex_output_file_handler.setFormatter(logging.Formatter("%(message)s"))
CODEX_OUTPUT_LOGGER.addHandler(_codex_output_file_handler)


def _resolve_codex_exec_binary(binary_override: str | None) -> tuple[str, str]:
    override = (binary_override or "").strip()
    if override:
        LOGGER.info("codex.exec.binary.resolve source=request value=%s", override)
        return override, "request"

    if DEFAULT_CODEX_EXEC_BINARY:
        LOGGER.info("codex.exec.binary.resolve source=env value=%s", DEFAULT_CODEX_EXEC_BINARY)
        return DEFAULT_CODEX_EXEC_BINARY, "env"

    for candidate in LOCAL_CODEX_EXEC_CANDIDATES:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            resolved = str(candidate)
            LOGGER.info("codex.exec.binary.resolve source=local value=%s", resolved)
            return resolved, "local"

    LOGGER.warning(
        "codex.exec.binary.resolve source=path value=codex checked_local_candidates=%s",
        [str(path) for path in LOCAL_CODEX_EXEC_CANDIDATES],
    )
    return "codex", "path"


def _track_codex_exec_pid(pid: int) -> None:
    with ACTIVE_CODEX_EXEC_PIDS_LOCK:
        ACTIVE_CODEX_EXEC_PIDS.add(pid)
    LOGGER.debug("codex.exec.track.add pid=%d", pid)


def _untrack_codex_exec_pid(pid: int) -> None:
    with ACTIVE_CODEX_EXEC_PIDS_LOCK:
        ACTIVE_CODEX_EXEC_PIDS.discard(pid)
    LOGGER.debug("codex.exec.track.remove pid=%d", pid)


def _snapshot_codex_exec_pids() -> list[int]:
    with ACTIVE_CODEX_EXEC_PIDS_LOCK:
        return sorted(ACTIVE_CODEX_EXEC_PIDS)


def _require_tool(tool_name: str) -> None:
    tool_path = shutil.which(tool_name)
    if tool_path is None:
        LOGGER.error("tool.check missing tool=%s", tool_name)
        raise RuntimeError(f"required tool is missing from PATH: {tool_name}")
    LOGGER.debug("tool.check found tool=%s path=%s", tool_name, tool_path)


def _short_text(text: str, max_len: int = 400) -> str:
    compact = " ".join(text.split())
    if len(compact) <= max_len:
        return compact
    return compact[:max_len] + "...<truncated>"


def _run_command(
    command: list[str], check: bool = True, input_text: str | None = None
) -> subprocess.CompletedProcess[str]:
    cmd_display = " ".join(shlex.quote(part) for part in command)
    LOGGER.debug(
        "cmd.start command=%s check=%s stdin_len=%d",
        cmd_display,
        check,
        len(input_text or ""),
    )
    start = time.monotonic()
    try:
        proc = subprocess.run(command, input=input_text, capture_output=True, text=True, check=check)
    except subprocess.CalledProcessError as exc:
        duration_ms = int((time.monotonic() - start) * 1000)
        LOGGER.error(
            "cmd.fail command=%s rc=%d duration_ms=%d stdout=%s stderr=%s",
            cmd_display,
            exc.returncode,
            duration_ms,
            _short_text(exc.stdout or ""),
            _short_text(exc.stderr or ""),
        )
        raise

    duration_ms = int((time.monotonic() - start) * 1000)
    LOGGER.debug(
        "cmd.done command=%s rc=%d duration_ms=%d stdout=%s stderr=%s",
        cmd_display,
        proc.returncode,
        duration_ms,
        _short_text(proc.stdout or ""),
        _short_text(proc.stderr or ""),
    )
    return proc


def _pid_is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _collect_codex_exec_pids() -> list[int]:
    LOGGER.info("codex.exec.collect_pids.start")
    _require_tool("pgrep")
    pid_strings: set[str] = set()

    proc = _run_command(["pgrep", "-f", r"(^|[[:space:]/])codex[[:space:]]+exec([[:space:]]|$)"], check=False)
    if proc.returncode in (0, 1):
        for line in proc.stdout.splitlines():
            item = line.strip()
            if item.isdigit():
                pid_strings.add(item)

    pids = sorted(int(pid) for pid in pid_strings)
    LOGGER.info("codex.exec.collect_pids.done count=%d pids=%s", len(pids), pids)
    return pids


def _collect_alive_codex_exec_pids() -> list[int]:
    pids = _collect_codex_exec_pids()
    alive_pids = [pid for pid in pids if _pid_is_alive(pid)]
    LOGGER.info("codex.exec.collect_alive_pids.done count=%d pids=%s", len(alive_pids), alive_pids)
    return alive_pids


def _kill_pids(pids: list[int]) -> list[int]:
    LOGGER.info("process.kill.start count=%d pids=%s", len(pids), pids)
    if not pids:
        LOGGER.info("process.kill.skip no_pids")
        return []

    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
            LOGGER.debug("process.kill.sigterm pid=%d", pid)
        except OSError:
            LOGGER.debug("process.kill.sigterm_missing pid=%d", pid)

    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        remaining = [pid for pid in pids if _pid_is_alive(pid)]
        if not remaining:
            LOGGER.info("process.kill.done via_sigterm")
            return []
        time.sleep(0.1)

    remaining = [pid for pid in pids if _pid_is_alive(pid)]
    for pid in remaining:
        try:
            os.kill(pid, signal.SIGKILL)
            LOGGER.debug("process.kill.sigkill pid=%d", pid)
        except OSError:
            LOGGER.debug("process.kill.sigkill_missing pid=%d", pid)

    time.sleep(0.2)
    still_alive = [pid for pid in remaining if _pid_is_alive(pid)]
    LOGGER.info("process.kill.done after_sigkill remaining=%s", still_alive)
    return still_alive


def _send_zulip_dm(zulip_script_path: str, message: str) -> str:
    LOGGER.info(
        "zulip.send.start script=%s message_len=%d message=%s",
        zulip_script_path,
        len(message),
        message,
    )
    script_path = Path(zulip_script_path)
    if not script_path.is_file():
        LOGGER.error("zulip.send.missing_script path=%s", script_path)
        raise RuntimeError(f"zulip helper script not found: {script_path}")

    _require_tool("node")
    proc = _run_command(["node", str(script_path), message], check=False)
    if proc.returncode != 0:
        details = proc.stderr.strip() or proc.stdout.strip() or "unknown error"
        LOGGER.error("zulip.send.fail details=%s", _short_text(details))
        raise RuntimeError(f"failed to send Zulip message: {details}")

    output = proc.stdout.strip()
    LOGGER.info("zulip.send.done output=%s", _short_text(output))
    return output


def _read_file_tail(path: Path, max_chars: int = 1200) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    if len(text) <= max_chars:
        return text
    return text[-max_chars:]


def _stream_codex_exec_output(proc: subprocess.Popen[str], request_id: str, log_path: Path) -> None:
    LOGGER.info(
        "codex.exec.output_stream.start request_id=%s pid=%d log_path=%s",
        request_id,
        proc.pid,
        log_path,
    )
    if proc.stdout is None:
        LOGGER.error(
            "codex.exec.output_stream.fail request_id=%s pid=%d reason=missing_stdout",
            request_id,
            proc.pid,
        )
        return

    try:
        with log_path.open("a", encoding="utf-8") as log_file:
            for raw_line in proc.stdout:
                log_file.write(raw_line)
                log_file.flush()
                CODEX_OUTPUT_LOGGER.info("%s", raw_line.rstrip("\r\n"))

            return_code = proc.wait()
            log_file.write(f"\n# codex_exec_return_code={return_code}\n")
            log_file.flush()
    except Exception as exc:  # pylint: disable=broad-except
        LOGGER.exception(
            "codex.exec.output_stream.fail request_id=%s pid=%d error=%s",
            request_id,
            proc.pid,
            exc,
        )
        return
    finally:
        _untrack_codex_exec_pid(proc.pid)

    LOGGER.info(
        "codex.exec.output_stream.done request_id=%s pid=%d return_code=%d",
        request_id,
        proc.pid,
        return_code,
    )


def _stop_active_codex_exec_processes(reason: str) -> list[int]:
    tracked_pids = _snapshot_codex_exec_pids()
    LOGGER.info(
        "codex.exec.stop_active.start reason=%s count=%d pids=%s",
        reason,
        len(tracked_pids),
        tracked_pids,
    )
    if not tracked_pids:
        LOGGER.info("codex.exec.stop_active.skip reason=%s no_pids", reason)
        return []

    remaining = _kill_pids(tracked_pids)
    with ACTIVE_CODEX_EXEC_PIDS_LOCK:
        for pid in tracked_pids:
            if pid not in remaining:
                ACTIVE_CODEX_EXEC_PIDS.discard(pid)

    LOGGER.info(
        "codex.exec.stop_active.done reason=%s remaining=%s",
        reason,
        remaining,
    )
    return remaining


def _start_codex_exec(
    workspace: str,
    prompt: str,
    request_id: str,
    codex_exec_binary: str,
    exec_delay_seconds: float,
    startup_check_seconds: float,
) -> dict[str, Any]:
    LOGGER.info(
        "codex.exec.start workspace=%s prompt_len=%d delay=%.2fs startup_check=%.2fs approval_policy=%s sandbox=%s",
        workspace,
        len(prompt),
        exec_delay_seconds,
        startup_check_seconds,
        ENFORCED_CODEX_APPROVAL_POLICY,
        ENFORCED_CODEX_EXEC_SANDBOX,
    )
    if not prompt.strip():
        LOGGER.error("codex.exec.fail empty_prompt")
        raise RuntimeError("codex_prompt is empty")

    workspace_path = Path(workspace).expanduser()
    if not workspace_path.is_dir():
        LOGGER.error("codex.exec.fail invalid_workspace workspace=%s", workspace_path)
        raise RuntimeError(f"workspace is not a directory: {workspace_path}")

    _require_tool(codex_exec_binary)
    if exec_delay_seconds > 0:
        LOGGER.debug("codex.exec.delay seconds=%.2f", exec_delay_seconds)
        time.sleep(exec_delay_seconds)

    DEFAULT_CODEX_EXEC_LOG_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    log_path = DEFAULT_CODEX_EXEC_LOG_DIR / f"codex-exec-{timestamp}-{request_id}.log"
    command = [
        codex_exec_binary,
        "--ask-for-approval",
        ENFORCED_CODEX_APPROVAL_POLICY,
        "exec",
        "--sandbox",
        ENFORCED_CODEX_EXEC_SANDBOX,
        "-C",
        str(workspace_path),
        prompt,
    ]
    cmd_display = " ".join(shlex.quote(part) for part in command)

    with log_path.open("w", encoding="utf-8") as log_file:
        log_file.write(f"# looper_request_id={request_id}\n")
        log_file.write(f"# workspace={workspace_path}\n")
        log_file.write(f"# command={cmd_display}\n\n")
        log_file.flush()

    proc = subprocess.Popen(  # pylint: disable=consider-using-with
        command,
        cwd=str(workspace_path),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        start_new_session=True,
    )
    if proc.stdout is None:
        raise RuntimeError("failed to capture codex exec output stream")
    _track_codex_exec_pid(proc.pid)

    output_thread = threading.Thread(
        target=_stream_codex_exec_output,
        args=(proc, request_id, log_path),
        daemon=True,
        name=f"codex-exec-output-{request_id}",
    )
    output_thread.start()

    LOGGER.info(
        "codex.exec.spawned request_id=%s pid=%d log_path=%s output_thread=%s",
        request_id,
        proc.pid,
        log_path,
        output_thread.name,
    )
    if startup_check_seconds > 0:
        LOGGER.debug("codex.exec.startup_check.sleep seconds=%.2f", startup_check_seconds)
        time.sleep(startup_check_seconds)

    startup_return_code = proc.poll()
    if startup_return_code not in (None, 0):
        output_thread.join(timeout=1.0)
        _untrack_codex_exec_pid(proc.pid)
        tail = _short_text(_read_file_tail(log_path))
        LOGGER.error(
            "codex.exec.fail request_id=%s pid=%d rc=%s tail=%s",
            request_id,
            proc.pid,
            startup_return_code,
            tail,
        )
        raise RuntimeError(
            "codex exec exited early "
            f"(rc={startup_return_code}, log_path={log_path}, tail={tail})"
        )

    result: dict[str, Any] = {
        "pid": proc.pid,
        "log_path": str(log_path),
        "command": cmd_display,
        "startup_return_code": startup_return_code,
        "output_thread": output_thread.name,
    }
    LOGGER.info("codex.exec.done result=%s", result)
    return result


def _latest_codex_exec_log_mtime(log_dir: Path) -> float | None:
    latest_mtime: float | None = None
    try:
        candidates = sorted(log_dir.glob("codex-exec-*.log"))
    except OSError as exc:
        LOGGER.warning("codex.exec.autopoll.logs_scan_failed log_dir=%s error=%s", log_dir, exc)
        return None

    for path in candidates:
        try:
            mtime = path.stat().st_mtime
        except OSError:
            continue
        if latest_mtime is None or mtime > latest_mtime:
            latest_mtime = mtime
    return latest_mtime


def _autopoll_start_codex_exec_if_inactive(
    workspace: str,
    prompt: str,
    codex_exec_binary: str,
    exec_delay_seconds: float,
    startup_check_seconds: float,
    log_dir: Path,
    stale_seconds: float,
) -> None:
    request_id = f"auto{uuid.uuid4().hex[:8]}"
    LOGGER.info(
        "codex.exec.autopoll.tick request_id=%s workspace=%s stale_seconds=%.2f",
        request_id,
        workspace,
        stale_seconds,
    )

    if not prompt.strip():
        LOGGER.warning("codex.exec.autopoll.skip request_id=%s reason=empty_prompt", request_id)
        return

    if not RUN_LOCK.acquire(blocking=False):
        LOGGER.info("codex.exec.autopoll.skip request_id=%s reason=run_lock_busy", request_id)
        return

    try:
        alive_pids = _collect_alive_codex_exec_pids()
        if alive_pids:
            LOGGER.info(
                "codex.exec.autopoll.skip request_id=%s reason=alive_tasks pids=%s",
                request_id,
                alive_pids,
            )
            return

        latest_log_mtime = _latest_codex_exec_log_mtime(log_dir)
        if latest_log_mtime is None:
            LOGGER.info(
                "codex.exec.autopoll.inactive request_id=%s reason=no_codex_exec_logs stale_seconds=%.2f",
                request_id,
                stale_seconds,
            )
        else:
            inactivity_seconds = max(0.0, time.time() - latest_log_mtime)
            if inactivity_seconds < stale_seconds:
                LOGGER.info(
                    "codex.exec.autopoll.skip request_id=%s reason=recent_log_activity inactivity_seconds=%.2f stale_seconds=%.2f",
                    request_id,
                    inactivity_seconds,
                    stale_seconds,
                )
                return
            LOGGER.info(
                "codex.exec.autopoll.inactive request_id=%s inactivity_seconds=%.2f stale_seconds=%.2f",
                request_id,
                inactivity_seconds,
                stale_seconds,
            )

        LOGGER.info("codex.exec.autopoll.start request_id=%s", request_id)
        result = _start_codex_exec(
            workspace=workspace,
            prompt=prompt,
            request_id=request_id,
            codex_exec_binary=codex_exec_binary,
            exec_delay_seconds=exec_delay_seconds,
            startup_check_seconds=startup_check_seconds,
        )
        LOGGER.info("codex.exec.autopoll.done request_id=%s result=%s", request_id, result)
    except Exception as exc:  # pylint: disable=broad-except
        LOGGER.exception("codex.exec.autopoll.fail request_id=%s error=%s", request_id, exc)
    finally:
        RUN_LOCK.release()


def _autopoll_loop(
    workspace: str,
    prompt: str,
    codex_exec_binary: str,
    exec_delay_seconds: float,
    startup_check_seconds: float,
    log_dir: Path,
    stale_seconds: float,
    poll_interval_seconds: float,
) -> None:
    LOGGER.info(
        "codex.exec.autopoll.loop.start workspace=%s poll_interval_seconds=%.2f codex_exec_binary=%s stale_seconds=%.2f log_dir=%s",
        workspace,
        poll_interval_seconds,
        codex_exec_binary,
        stale_seconds,
        log_dir,
    )
    while not AUTO_POLL_STOP_EVENT.is_set():
        _autopoll_start_codex_exec_if_inactive(
            workspace=workspace,
            prompt=prompt,
            codex_exec_binary=codex_exec_binary,
            exec_delay_seconds=exec_delay_seconds,
            startup_check_seconds=startup_check_seconds,
            log_dir=log_dir,
            stale_seconds=stale_seconds,
        )
        if AUTO_POLL_STOP_EVENT.wait(poll_interval_seconds):
            break
    LOGGER.info("codex.exec.autopoll.loop.stop")


def _get_token_from_request() -> str:
    auth_header = (request.headers.get("Authorization") or "").strip()
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()
    return (request.headers.get("X-Looper-Token") or "").strip()


def _validate_non_negative_float(payload: dict[str, Any], key: str, default: float) -> float:
    if key not in payload:
        return default

    value = payload[key]
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"'{key}' must be a number") from exc
    if parsed < 0:
        raise ValueError(f"'{key}' must be >= 0")
    return parsed


@app.before_request
def _log_request_start() -> None:
    g.request_id = uuid.uuid4().hex[:8]
    g.request_start_monotonic = time.monotonic()
    LOGGER.info(
        "http.start request_id=%s method=%s path=%s remote=%s user_agent=%s",
        g.request_id,
        request.method,
        request.path,
        request.remote_addr,
        request.user_agent.string,
    )


@app.after_request
def _log_request_end(response):  # type: ignore[no-untyped-def]
    start = getattr(g, "request_start_monotonic", None)
    duration_ms = -1 if start is None else int((time.monotonic() - start) * 1000)
    request_id = getattr(g, "request_id", "unknown")
    LOGGER.info(
        "http.end request_id=%s method=%s path=%s status=%d duration_ms=%d",
        request_id,
        request.method,
        request.path,
        response.status_code,
        duration_ms,
    )
    return response


@app.get("/health")
def health() -> tuple[Any, int]:
    LOGGER.debug("health.check")
    return jsonify({"ok": True}), 200


@app.post("/run")
def run() -> tuple[Any, int]:
    request_id = getattr(g, "request_id", "unknown")
    LOGGER.info("run.start request_id=%s", request_id)
    expected_token = os.getenv("LOOPER_API_TOKEN", "").strip()
    if expected_token:
        LOGGER.debug("run.auth.required request_id=%s", request_id)
        provided_token = _get_token_from_request()
        if provided_token != expected_token:
            LOGGER.warning("run.auth.failed request_id=%s", request_id)
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        LOGGER.info("run.auth.ok request_id=%s", request_id)

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        LOGGER.warning("run.payload.invalid_json request_id=%s", request_id)
        payload = {}
    LOGGER.info("run.payload.keys request_id=%s keys=%s", request_id, sorted(payload.keys()))

    zulip_message = str(payload.get("zulip_message", "")).strip()
    if not zulip_message:
        LOGGER.warning("run.payload.missing_zulip_message request_id=%s", request_id)
        return jsonify({"ok": False, "error": "missing 'zulip_message'"}), 400
    codex_prompt = str(payload.get("codex_prompt", payload.get("prompt", DEFAULT_CODEX_PROMPT))).strip()

    workspace = str(payload.get("workspace", DEFAULT_WORKSPACE)).strip() or DEFAULT_WORKSPACE
    zulip_script_path = str(payload.get("zulip_script_path", DEFAULT_ZULIP_DM_SCRIPT)).strip() or DEFAULT_ZULIP_DM_SCRIPT
    codex_exec_binary_override: str | None = None
    if "codex_exec_binary" in payload:
        codex_exec_binary_override = str(payload.get("codex_exec_binary", "")).strip()
    codex_exec_binary, codex_exec_binary_source = _resolve_codex_exec_binary(codex_exec_binary_override)

    try:
        if "codex_exec_delay_seconds" in payload:
            codex_exec_delay_seconds = _validate_non_negative_float(
                payload, "codex_exec_delay_seconds", DEFAULT_CODEX_EXEC_DELAY_SECONDS
            )
        elif any(
            key in payload
            for key in (
                "startup_delay_seconds",
                "sidebar_delay_seconds",
                "new_task_delay_seconds",
                "prompt_send_delay_seconds",
            )
        ):
            codex_exec_delay_seconds = 0.0
            for key in (
                "startup_delay_seconds",
                "sidebar_delay_seconds",
                "new_task_delay_seconds",
                "prompt_send_delay_seconds",
            ):
                codex_exec_delay_seconds += _validate_non_negative_float(payload, key, 0.0)
        else:
            codex_exec_delay_seconds = DEFAULT_CODEX_EXEC_DELAY_SECONDS

        codex_exec_startup_check_seconds = _validate_non_negative_float(
            payload,
            "codex_exec_startup_check_seconds",
            DEFAULT_CODEX_EXEC_STARTUP_CHECK_SECONDS,
        )
    except ValueError as exc:
        LOGGER.warning("run.payload.invalid_delay request_id=%s error=%s", request_id, exc)
        return jsonify({"ok": False, "error": str(exc)}), 400

    LOGGER.info(
        "run.config request_id=%s workspace=%s zulip_script=%s codex_exec_binary=%s codex_exec_binary_source=%s "
        "codex_exec_delay=%.2f codex_exec_startup_check=%.2f approval_policy=%s sandbox=%s "
        "zulip_message_len=%d codex_prompt_len=%d",
        request_id,
        workspace,
        zulip_script_path,
        codex_exec_binary,
        codex_exec_binary_source,
        codex_exec_delay_seconds,
        codex_exec_startup_check_seconds,
        ENFORCED_CODEX_APPROVAL_POLICY,
        ENFORCED_CODEX_EXEC_SANDBOX,
        len(zulip_message),
        len(codex_prompt),
    )

    if not RUN_LOCK.acquire(blocking=False):
        LOGGER.warning("run.lock.busy request_id=%s", request_id)
        return jsonify({"ok": False, "error": "busy: another run is in progress"}), 409

    try:
        LOGGER.info("run.step request_id=%s action=send_zulip", request_id)
        zulip_output = _send_zulip_dm(zulip_script_path, zulip_message)
        LOGGER.info("run.step request_id=%s action=collect_and_kill_codex_exec", request_id)
        old_codex_exec_pids = _collect_codex_exec_pids()
        remaining_pids_after_kill = _kill_pids(old_codex_exec_pids)
        codex_exec_result: dict[str, Any] | None = None
        if codex_prompt:
            LOGGER.info("run.step request_id=%s action=start_codex_exec", request_id)
            codex_exec_result = _start_codex_exec(
                workspace=workspace,
                prompt=codex_prompt,
                request_id=request_id,
                codex_exec_binary=codex_exec_binary,
                exec_delay_seconds=codex_exec_delay_seconds,
                startup_check_seconds=codex_exec_startup_check_seconds,
            )
        else:
            LOGGER.info("run.step request_id=%s action=skip_codex_exec reason=empty_prompt", request_id)
    except Exception as exc:  # pylint: disable=broad-except
        LOGGER.exception("run.fail request_id=%s error=%s", request_id, exc)
        return jsonify({"ok": False, "error": str(exc)}), 500
    finally:
        RUN_LOCK.release()
        LOGGER.debug("run.lock.released request_id=%s", request_id)

    LOGGER.info(
        "run.success request_id=%s killed_codex_exec_pids=%s remaining_pids=%s codex_exec_started=%s codex_exec_result=%s",
        request_id,
        old_codex_exec_pids,
        remaining_pids_after_kill,
        bool(codex_prompt),
        codex_exec_result,
    )

    return (
        jsonify(
            {
                "ok": True,
                "zulip_output": zulip_output,
                "killed_codex_exec_pids": old_codex_exec_pids,
                "remaining_vscode_pids": remaining_pids_after_kill,
                "remaining_codex_exec_pids": remaining_pids_after_kill,
                "workspace": workspace,
                "codex_exec_binary": codex_exec_binary,
                "codex_exec_binary_source": codex_exec_binary_source,
                "codex_exec_started": bool(codex_prompt),
                "codex_exec_result": codex_exec_result,
                "codex_exec_approval_policy": ENFORCED_CODEX_APPROVAL_POLICY,
                "codex_exec_sandbox": ENFORCED_CODEX_EXEC_SANDBOX,
                # Backward compatibility aliases for existing wrappers.
                "killed_vscode_pids": old_codex_exec_pids,
                "codex_prompt_sent": bool(codex_prompt),
                "codex_send_result": codex_exec_result,
            }
        ),
        200,
    )


if __name__ == "__main__":
    host = os.getenv("LOOPER_HOST", "0.0.0.0")
    port = int(os.getenv("LOOPER_PORT", "3456"))
    idle_poll_seconds = DEFAULT_IDLE_POLL_SECONDS
    idle_log_stale_seconds = DEFAULT_IDLE_LOG_STALE_SECONDS
    if idle_poll_seconds <= 0:
        LOGGER.warning(
            "codex.exec.autopoll.invalid_interval value=%.2f fallback=300.00",
            idle_poll_seconds,
        )
        idle_poll_seconds = 300.0
    if idle_log_stale_seconds <= 0:
        LOGGER.warning(
            "codex.exec.autopoll.invalid_stale_seconds value=%.2f fallback=600.00",
            idle_log_stale_seconds,
        )
        idle_log_stale_seconds = 600.0

    autopoll_thread: threading.Thread | None = None
    if DEFAULT_AUTO_START_WHEN_IDLE:
        autopoll_codex_exec_binary, autopoll_binary_source = _resolve_codex_exec_binary(None)
        autopoll_thread = threading.Thread(
            target=_autopoll_loop,
            args=(
                DEFAULT_WORKSPACE,
                DEFAULT_CODEX_PROMPT,
                autopoll_codex_exec_binary,
                DEFAULT_CODEX_EXEC_DELAY_SECONDS,
                DEFAULT_CODEX_EXEC_STARTUP_CHECK_SECONDS,
                DEFAULT_CODEX_EXEC_LOG_DIR,
                idle_log_stale_seconds,
                idle_poll_seconds,
            ),
            daemon=True,
            name="codex-autopoll",
        )
        autopoll_thread.start()
        LOGGER.info(
            "codex.exec.autopoll.enabled interval_seconds=%.2f workspace=%s codex_exec_binary=%s codex_exec_binary_source=%s stale_seconds=%.2f log_dir=%s",
            idle_poll_seconds,
            DEFAULT_WORKSPACE,
            autopoll_codex_exec_binary,
            autopoll_binary_source,
            idle_log_stale_seconds,
            DEFAULT_CODEX_EXEC_LOG_DIR,
        )
    else:
        LOGGER.info("codex.exec.autopoll.disabled")

    atexit.register(lambda: _stop_active_codex_exec_processes("atexit"))
    LOGGER.info(
        "server.start host=%s port=%d log_level=%s workspace=%s zulip_script=%s server_log_path=%s codex_exec_log_dir=%s autopoll_enabled=%s autopoll_interval_seconds=%.2f autopoll_stale_seconds=%.2f",
        host,
        port,
        DEFAULT_LOG_LEVEL,
        DEFAULT_WORKSPACE,
        DEFAULT_ZULIP_DM_SCRIPT,
        DEFAULT_SERVER_LOG_PATH,
        DEFAULT_CODEX_EXEC_LOG_DIR,
        DEFAULT_AUTO_START_WHEN_IDLE,
        idle_poll_seconds,
        idle_log_stale_seconds,
    )
    try:
        app.run(host=host, port=port)
    finally:
        AUTO_POLL_STOP_EVENT.set()
        if autopoll_thread is not None:
            autopoll_thread.join(timeout=2.0)
            LOGGER.info(
                "codex.exec.autopoll.thread_stopped alive=%s",
                autopoll_thread.is_alive(),
            )
        _stop_active_codex_exec_processes("server_shutdown")
