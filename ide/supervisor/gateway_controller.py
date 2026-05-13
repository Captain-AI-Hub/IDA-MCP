"""Gateway control via the gateway's own HTTP API.

All operations (status, start, stop) use the gateway's internal HTTP API
mounted at /internal/* on the gateway port, or direct TCP port probing.
Stop falls back to force-killing the process when graceful shutdown fails.
Every HTTP request and response is logged via an optional log callback.
"""

from __future__ import annotations

import json
import socket
import subprocess
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Callable

from shared.platform import display_path as _display_path

from . import process_manager
from .config_store import IdeConfigStore
from .models import (
    GatewayState,
    GatewayStatus,
    DEFAULT_GATEWAY_HOST,
    DEFAULT_GATEWAY_PORT,
    DEFAULT_GATEWAY_PATH,
)


def _error_status(message: str) -> GatewayStatus:
    return GatewayStatus(
        state=GatewayState.ERROR,
        alive=False,
        proxy_alive=False,
        enabled=True,
        host=DEFAULT_GATEWAY_HOST,
        port=DEFAULT_GATEWAY_PORT,
        path=DEFAULT_GATEWAY_PATH,
        last_error=message,
        raw={"error": message},
    )


class GatewayController:
    def __init__(
        self,
        config_store: IdeConfigStore | None = None,
        log: Callable[[str], None] | None = None,
        python_path: str | None = None,
    ) -> None:
        self.config_store = config_store or IdeConfigStore()
        self._log = log
        self._python_path = python_path

    def _log_msg(self, msg: str) -> None:
        if self._log:
            self._log(msg)

    def _gateway_params(self) -> tuple[str, int, str]:
        config = self.config_store.load()
        host = config.gateway_host or DEFAULT_GATEWAY_HOST
        port = config.gateway_port or DEFAULT_GATEWAY_PORT
        path = config.gateway_path or DEFAULT_GATEWAY_PATH
        return host, port, path

    def _internal_url(self, endpoint: str) -> str:
        host, port, _ = self._gateway_params()
        return f"http://{host}:{port}/internal{endpoint}"

    # ------------------------------------------------------------------
    # HTTP helpers with logging
    # ------------------------------------------------------------------
    def _tcp_port_open(self, host: str, port: int, timeout: float = 2.0) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    def _http_get(
        self, url: str, timeout: float = 3.0
    ) -> tuple[int, dict[str, Any] | None]:
        """GET url, return (status_code, parsed_json_or_None)."""
        self._log_msg(f"GET {url}")
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read())
                code = resp.status
                self._log_msg(f"← {code} {json.dumps(body, ensure_ascii=False)[:300]}")
                return code, body
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            self._log_msg(f"← {exc.code} {raw[:300]}")
            try:
                return exc.code, json.loads(raw)
            except json.JSONDecodeError:
                return exc.code, {"raw": raw}
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            self._log_msg(f"← error: {exc}")
            return 0, None

    def _http_post(
        self, url: str, body: dict[str, Any] | None = None, timeout: float = 10.0
    ) -> tuple[int, dict[str, Any] | None]:
        """POST url with json body, return (status_code, parsed_json_or_None)."""
        data = json.dumps(body or {}).encode("utf-8")
        self._log_msg(
            f"POST {url}  body={json.dumps(body or {}, ensure_ascii=False)[:200]}"
        )
        try:
            req = urllib.request.Request(url, data=data, method="POST")
            req.add_header("Content-Type", "application/json")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                resp_body = json.loads(resp.read())
                code = resp.status
                self._log_msg(
                    f"← {code} {json.dumps(resp_body, ensure_ascii=False)[:300]}"
                )
                return code, resp_body
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            self._log_msg(f"← {exc.code} {raw[:300]}")
            try:
                return exc.code, json.loads(raw)
            except json.JSONDecodeError:
                return exc.code, {"raw": raw}
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            self._log_msg(f"← error: {exc}")
            return 0, None

    # ------------------------------------------------------------------
    # Status — pure HTTP, no subprocess
    # ------------------------------------------------------------------
    def status(self) -> GatewayStatus:
        host, port, path = self._gateway_params()

        # 1. TCP port probe
        self._log_msg(f"TCP probe {host}:{port}...")
        if not self._tcp_port_open(host, port, timeout=2.0):
            self._log_msg(f"Port {port} closed — gateway stopped")
            return GatewayStatus(
                state=GatewayState.STOPPED,
                alive=False,
                proxy_alive=False,
                enabled=True,
                host=host,
                port=port,
                path=path,
                instance_count=0,
                last_error=None,
                raw={},
            )
        self._log_msg(f"Port {port} open")

        # 2. Healthz
        _, health = self._http_get(self._internal_url("/healthz"))
        if health is None:
            self._log_msg("healthz failed — gateway starting?")
            return GatewayStatus(
                state=GatewayState.STARTING,
                alive=True,
                proxy_alive=False,
                enabled=True,
                host=host,
                port=port,
                path=path,
                instance_count=0,
                last_error=None,
                raw={"port_open": True},
            )

        alive = bool(health.get("ok"))
        self._log_msg(f"healthz: ok={alive}")

        # 3. Instances
        _, instances_data = self._http_get(self._internal_url("/instances"))
        instance_list: list[dict[str, Any]] = []
        if isinstance(instances_data, list):
            instance_list = instances_data
        elif isinstance(instances_data, dict) and "instances" in instances_data:
            instance_list = instances_data["instances"]
        instance_count = len(instance_list)
        self._log_msg(f"instances: {instance_count}")

        # 4. Proxy status
        _, proxy_data = self._http_get(self._internal_url("/proxy_status"))
        proxy_alive = (
            bool(proxy_data.get("alive")) if isinstance(proxy_data, dict) else alive
        )

        state = GatewayState.RUNNING if alive else GatewayState.STOPPED
        self._log_msg(
            f"Status: {state.value}, alive={alive}, proxy={proxy_alive}, instances={instance_count}"
        )
        return GatewayStatus(
            state=state,
            alive=alive,
            proxy_alive=proxy_alive,
            enabled=True,
            host=host,
            port=port,
            path=path,
            instance_count=instance_count,
            instances=instance_list,
            last_error=health.get("error") if isinstance(health, dict) else None,
            raw=health,
        )

    # ------------------------------------------------------------------
    # Start — HTTP if already running, subprocess otherwise
    # ------------------------------------------------------------------
    def start(self) -> GatewayStatus:
        host, port, _ = self._gateway_params()

        self._log_msg(f"Checking if gateway is already running on {host}:{port}...")
        if self._tcp_port_open(host, port, timeout=1.0):
            self._log_msg("Gateway already running, fetching status...")
            return self.status()

        self._log_msg("Port not open, launching gateway via subprocess...")
        return self._subprocess_start()

    # ------------------------------------------------------------------
    # Stop — POST /internal/shutdown (graceful, then force)
    # ------------------------------------------------------------------
    def stop(self) -> GatewayStatus:
        host, port, path = self._gateway_params()

        self._log_msg(f"Checking {host}:{port} before stop...")
        if not self._tcp_port_open(host, port, timeout=1.0):
            self._log_msg("Port closed — gateway already stopped")
            return GatewayStatus(
                state=GatewayState.STOPPED,
                alive=False,
                proxy_alive=False,
                enabled=True,
                host=host,
                port=port,
                path=path,
                instance_count=0,
                last_error=None,
                raw={},
            )

        # 1. Graceful shutdown (no force)
        code, result = self._http_post(self._internal_url("/shutdown"), body={})
        if code == 409:
            # Instances still registered — try force shutdown
            msg = (result or {}).get("error", "Shutdown refused")
            count = (result or {}).get("instance_count", "?")
            self._log_msg(
                f"Graceful shutdown refused: {msg} (instances: {count}), retrying with force..."
            )
            code, result = self._http_post(
                self._internal_url("/shutdown"), body={"force": True}
            )

        if code == 0 or result is None:
            # Network error — gateway not responding, force kill by port
            self._log_msg(
                "Shutdown request failed (network error), force-killing by port..."
            )
            return self._force_stop(host, port, path)

        if isinstance(result, dict) and result.get("error"):
            # Server responded but refused even with force
            self._log_msg(f"Force shutdown also failed: {result['error']}")
            return self._force_stop(host, port, path)

        # Shutdown accepted — wait for port to close
        self._log_msg("Shutdown accepted, waiting for port to close...")
        for _ in range(20):
            if not self._tcp_port_open(host, port, timeout=0.5):
                self._log_msg("Gateway stopped (port closed)")
                break
            time.sleep(0.25)
        else:
            # Port still open after waiting — force kill
            self._log_msg("Port did not close in time, force-killing...")
            return self._force_stop(host, port, path)

        return self.status()

    def _force_stop(
        self, host: str, port: int, path: str
    ) -> GatewayStatus:
        """Force-kill the process listening on *port* and return STOPPED status."""
        killed = self._kill_port(port)
        if killed:
            self._log_msg(f"Force-killed process on port {port}")
        else:
            self._log_msg(f"Could not find/kill process on port {port}")
        # Brief wait for port release
        time.sleep(0.3)
        return GatewayStatus(
            state=GatewayState.STOPPED,
            alive=False,
            proxy_alive=False,
            enabled=True,
            host=host,
            port=port,
            path=path,
            instance_count=0,
            last_error=None if killed else f"Force stop attempted on port {port}",
            raw={"force_killed": killed},
        )

    @staticmethod
    def _kill_port(port: int) -> bool:
        return process_manager.kill_process_on_port(port)

    # ------------------------------------------------------------------
    # Subprocess fallback for starting
    # ------------------------------------------------------------------
    def _subprocess_start(self) -> GatewayStatus:
        config = self.config_store.load()
        if not config.plugin_dir:
            msg = "Set plugin_dir before starting the gateway."
            self._log_msg(f"ERROR: {msg}")
            return _error_status(msg)

        plugin_dir = Path(config.plugin_dir)
        if not plugin_dir.exists():
            msg = f"plugin_dir ({_display_path(plugin_dir)}) does not exist."
            self._log_msg(f"ERROR: {msg}")
            return _error_status(msg)

        # Verify command.py exists in the installed plugin
        command_script = plugin_dir / "ida_mcp" / "command.py"
        if not command_script.exists():
            msg = f"command.py not found at {_display_path(command_script)}. Run install first."
            self._log_msg(f"ERROR: {msg}")
            return _error_status(msg)

        # python_path comes from ida_python
        python_path_raw = self._python_path or ""
        if not python_path_raw:
            msg = "Set ida_python before starting the gateway."
            self._log_msg(f"ERROR: {msg}")
            return _error_status(msg)
        python_path = Path(python_path_raw)
        if not python_path.exists():
            msg = f"ida_python ({_display_path(python_path)}) does not exist."
            self._log_msg(f"ERROR: {msg}")
            return _error_status(msg)

        # command.py handles its own sys.path fixup, so no PYTHONPATH needed.
        # Avoid setting PYTHONPATH to prevent stdlib shadowing in IDA's plugin dir.

        # Use command.py which handles gateway start (including spawning
        # registry_server as a detached process) and returns JSON on stdout.
        cmd = [str(python_path), str(command_script), "gateway", "start", "--json"]
        self._log_msg(f"$ {' '.join(_display_path(c) for c in cmd)}")

        # Use temp files instead of pipes for stdout/stderr.  On Windows,
        # ``subprocess.run(capture_output=True)`` creates anonymous pipes
        # whose write handles are inherited by grandchild processes (e.g.
        # registry_server.py spawned by command.py).  Because the gateway
        # server never exits, those handles stay open and communicate()
        # blocks forever waiting for EOF.  Temp files avoid this entirely.
        import tempfile

        try:
            with (
                tempfile.NamedTemporaryFile(
                    mode="w", suffix=".txt", delete=False
                ) as out_f,
                tempfile.NamedTemporaryFile(
                    mode="w", suffix=".txt", delete=False
                ) as err_f,
            ):
                out_path = out_f.name
                err_path = err_f.name

            proc = subprocess.Popen(
                cmd,
                stdout=open(out_path, "w"),
                stderr=open(err_path, "w"),
                text=True,
            )
            try:
                proc.wait(timeout=max(config.request_timeout, 30))
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                self._log_msg("command.py timed out")
                return _error_status("Gateway start timed out")

            stdout = Path(out_path).read_text(encoding="utf-8", errors="replace")
            stderr = Path(err_path).read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            self._log_msg(f"Spawn error: {exc}")
            return _error_status(str(exc))
        finally:
            for p in (out_path, err_path):
                try:
                    Path(p).unlink(missing_ok=True)
                except Exception:
                    pass

        self._log_msg(f"stdout: {stdout.strip()[:500]}")
        if stderr.strip():
            self._log_msg(f"stderr: {stderr.strip()[:500]}")

        if proc.returncode != 0:
            msg = (stderr or stdout).strip() or "gateway start failed"
            self._log_msg(f"Exit code {proc.returncode}: {msg[:300]}")
            return _error_status(msg)

        self._log_msg("Gateway launched, checking status...")
        return self.status()
