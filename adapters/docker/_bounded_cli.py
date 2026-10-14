"""Bounded trusted CLI transport; container authority belongs to the caller."""
from __future__ import annotations

import os
import selectors
import subprocess
import time
from typing import Sequence


class OutputLimitExceeded(RuntimeError):
    pass


def run_cli(
    argv: Sequence[str], *, timeout: float, stdout_limit: int = 4096,
    stderr_limit: int = 4096,
) -> subprocess.CompletedProcess[bytes]:
    """Bound both captured streams while reading, and reap the exact CLI child."""
    proc = subprocess.Popen(
        argv, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE if stdout_limit else subprocess.DEVNULL,
        stderr=subprocess.PIPE if stderr_limit else subprocess.DEVNULL,
        shell=False,
    )
    deadline = time.monotonic() + timeout
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        with selectors.DefaultSelector() as selector:
            for name, limit in (("stdout", stdout_limit), ("stderr", stderr_limit)):
                stream = getattr(proc, name)
                if stream is not None:
                    selector.register(stream, selectors.EVENT_READ, (name, limit))
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired("trusted Docker CLI", timeout)
                ready = selector.select(remaining)
                if not ready:
                    raise subprocess.TimeoutExpired("trusted Docker CLI", timeout)
                for key, _ in ready:
                    name, limit = key.data
                    chunk = os.read(key.fd, min(65536, limit + 1 - len(buffers[name])))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    buffers[name].extend(chunk)
                    if len(buffers[name]) > limit:
                        raise OutputLimitExceeded(f"Docker CLI {name} exceeded byte limit")
        returncode = proc.wait(timeout=max(0, deadline - time.monotonic()))
        return subprocess.CompletedProcess(list(argv), returncode, bytes(buffers["stdout"]), bytes(buffers["stderr"]))
    except BaseException:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=5)
        raise
    finally:
        for stream in (proc.stdout, proc.stderr):
            if stream is not None:
                stream.close()
