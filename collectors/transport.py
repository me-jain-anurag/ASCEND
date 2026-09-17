"""
How a probe reaches a host.

Probes never shell out themselves — they are handed a Transport and call
``run()`` / ``read_file()``. That is what lets the same probe code run against a
Docker container today, an SSH-reachable VM tomorrow (the docs/02 section 6
fallback), or the local machine in a unit test, with no change to the probe.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


@dataclass
class Result:
    exit_code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


class Transport:
    """Interface. Subclasses implement run() and read_file()."""

    name = "abstract"

    def run(self, host: str, argv: list[str], timeout: int = 30) -> Result:
        raise NotImplementedError

    def read_file(self, host: str, path: str, timeout: int = 30) -> str | None:
        """Return the file's text, or None if it does not exist / is unreadable."""
        res = self.run(host, ["cat", path], timeout=timeout)
        return res.stdout if res.ok else None

    def available_hosts(self) -> list[str]:
        raise NotImplementedError


class DockerTransport(Transport):
    """`docker exec` into the lab containers.

    Commands run as root inside the container. That is correct for a collector:
    a fact collector is an *inventory* tool with administrative read access, not
    an attacker. It observes the configuration; it does not exploit it.
    """

    name = "docker"

    def __init__(self, prefix: str = "ascend-", binary: str = "docker"):
        self.prefix = prefix
        self.binary = binary
        if shutil.which(binary) is None:
            raise RuntimeError(
                f"{binary!r} not found on PATH. Install Docker, or run the collector "
                f"with --transport local against a non-container target."
            )

    def container(self, host: str) -> str:
        return f"{self.prefix}{host}"

    def run(self, host: str, argv: list[str], timeout: int = 30) -> Result:
        cmd = [self.binary, "exec", self.container(host), *argv]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return Result(124, "", f"timeout after {timeout}s: {' '.join(argv)}")
        except FileNotFoundError as exc:
            return Result(127, "", str(exc))
        return Result(p.returncode, p.stdout, p.stderr)

    def available_hosts(self) -> list[str]:
        """Every running container carrying our prefix, in name order."""
        p = subprocess.run(
            [self.binary, "ps", "--filter", f"name={self.prefix}",
             "--format", "{{.Names}}"],
            capture_output=True, text=True,
        )
        if p.returncode != 0:
            raise RuntimeError(f"`docker ps` failed: {p.stderr.strip()}")
        names = [n.strip() for n in p.stdout.splitlines() if n.strip()]
        return sorted(n[len(self.prefix):] for n in names if n.startswith(self.prefix))


class LocalTransport(Transport):
    """Run against this machine. Used by the unit tests and by --transport local."""

    name = "local"

    def __init__(self, hostname: str = "localhost"):
        self.hostname = hostname

    def run(self, host: str, argv: list[str], timeout: int = 30) -> Result:
        try:
            p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return Result(124, "", f"timeout after {timeout}s")
        except FileNotFoundError as exc:
            return Result(127, "", str(exc))
        return Result(p.returncode, p.stdout, p.stderr)

    def available_hosts(self) -> list[str]:
        return [self.hostname]
