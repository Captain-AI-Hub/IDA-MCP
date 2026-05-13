"""Process management helpers for the gateway supervisor."""

from __future__ import annotations

import os
import signal
import subprocess
from pathlib import Path


def _is_gateway_process(pid: int) -> bool:
    names: list[str] = []
    proc_comm = Path(f"/proc/{pid}/comm")
    if proc_comm.exists():
        try:
            names.append(proc_comm.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            pass
    try:
        proc = subprocess.run(
            ["ps", "-p", str(pid), "-o", "comm="],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if proc.returncode == 0:
            names.append(proc.stdout)
    except (OSError, subprocess.SubprocessError):
        pass
    return any(
        marker in name.lower()
        for name in names
        for marker in ("gateway", "uvicorn", "registry_server")
    )


def kill_process_on_port(port: int) -> bool:
    """Kill the process listening on the given port. Returns True on success."""
    try:
        if os.name == "nt":
            proc = subprocess.run(
                ["netstat", "-ano", "-p", "TCP"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            for line in proc.stdout.splitlines():
                parts = line.split()
                expected_ports = {f"0.0.0.0:{port}", f"127.0.0.1:{port}"}
                if (
                    len(parts) >= 5
                    and parts[3] == "LISTENING"
                    and parts[1] in expected_ports
                    and any(expected in line for expected in expected_ports)
                ):
                    pid = parts[-1]
                    if not pid.isdigit():
                        continue
                    kill_result = subprocess.run(
                        ["taskkill", "/F", "/T", "/PID", pid],
                        capture_output=True,
                        timeout=5,
                    )
                    return kill_result.returncode == 0
            return False

        proc = subprocess.run(
            ["lsof", "-ti", f":{port}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        pids = proc.stdout.strip().split()
        killed = False
        if pids:
            for pid_str in pids:
                if pid_str.isdigit():
                    pid = int(pid_str)
                    if not _is_gateway_process(pid):
                        continue
                    try:
                        os.kill(pid, signal.SIGKILL)
                        killed = True
                    except ProcessLookupError:
                        continue
            return killed
        return False
    except Exception:
        return False
