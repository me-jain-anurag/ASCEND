"""Docker SDK interface for the execution verifier.

Everything the verifier does to a lab container goes through this module:
running commands, resetting hosts, reading the canary token.  Nothing else
in verifier/ imports ``docker`` directly.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path


# ── Lazy Docker client ────────────────────────────────────────────────────────
# Imported lazily so that modules that only need the function signatures (tests
# with mocked exec_as) don't require the docker SDK at import time.

_client = None


def _docker_client():
    global _client
    if _client is None:
        import docker
        _client = docker.from_env()
    return _client


# ── Container name resolution ─────────────────────────────────────────────────

def _container_name(host: str, prefix: str = "ascend-") -> str:
    """Map a logical host name to its Docker container name."""
    return f"{prefix}{host}"


# ── Core primitives ──────────────────────────────────────────────────────────

def exec_as(
    host: str,
    user: str,
    cmd: list[str],
    timeout: int = 30,
    prefix: str = "ascend-",
) -> tuple[int, str, str]:
    """Run *cmd* on a lab container as *user*.

    Returns ``(exit_code, stdout, stderr)``.  The *timeout* is a best-effort
    guard; Docker's ``exec_run`` doesn't natively support it, so we rely on
    the command itself to finish within a reasonable time.
    """
    client = _docker_client()
    container = client.containers.get(_container_name(host, prefix))
    res = container.exec_run(
        cmd,
        user=user,
        demux=True,
        tty=False,
        environment={"LANG": "C"},
    )
    out_bytes, err_bytes = res.output
    stdout = (out_bytes or b"").decode(errors="replace")
    stderr = (err_bytes or b"").decode(errors="replace")
    return res.exit_code, stdout, stderr


def reset(
    host: str,
    mode: str = "recreate",
    compose_file: str = "lab/docker-compose.yml",
    prefix: str = "ascend-",
) -> None:
    """Reset *host* to a clean state.

    After reset the container is running with a freshly planted canary and
    all weaknesses in their original state.
    """
    if mode != "recreate":
        raise ValueError(f"unknown reset mode {mode!r}")

    # Resolve compose file relative to the repo root
    repo_root = Path(__file__).resolve().parent.parent
    compose_path = repo_root / compose_file

    subprocess.run(
        [
            "docker", "compose",
            "-f", str(compose_path),
            "up", "-d", "--force-recreate", "--no-deps",
            host,
        ],
        check=True,
        capture_output=True,
    )
    wait_healthy(host, prefix=prefix)
    assert_canary_present(host, prefix=prefix)


def wait_healthy(
    host: str,
    timeout: int = 30,
    prefix: str = "ascend-",
) -> None:
    """Block until SSH is listening on *host* (or until *timeout* expires)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            code, out, _ = exec_as(
                host, "root",
                ["sh", "-c", "ss -ltn 2>/dev/null | grep -q ':22 '"],
                prefix=prefix,
            )
            if code == 0:
                return
        except Exception:
            pass
        time.sleep(0.5)
    raise TimeoutError(f"{host}: SSH not ready within {timeout}s after reset")


def canary_token(host: str, canary_path: str = "/root/.ascend_canary", prefix: str = "ascend-") -> str:
    """Read the root-only canary token from inside *host*.

    This reads as root — only the verifier's signal module should call this
    to get the expected value for comparison.
    """
    code, out, err = exec_as(host, "root", ["cat", canary_path], prefix=prefix)
    token = out.strip()
    if code != 0 or not token:
        raise RuntimeError(
            f"cannot read canary on {host} (exit {code}): {err or out}"
        )
    return token


def assert_canary_present(host: str, prefix: str = "ascend-") -> None:
    """Verify the canary file exists and is readable by root after a reset."""
    canary_token(host, prefix=prefix)


def file_exists(host: str, path: str, prefix: str = "ascend-") -> bool:
    """Check whether *path* exists inside *host*."""
    code, _, _ = exec_as(host, "root", ["test", "-f", path], prefix=prefix)
    return code == 0


def container_image_digest(host: str, prefix: str = "ascend-") -> str:
    """Return the image digest (sha256:...) for *host*'s container image."""
    try:
        client = _docker_client()
        container = client.containers.get(_container_name(host, prefix))
        img = container.image
        digests = img.attrs.get("RepoDigests", [])
        return digests[0] if digests else img.id
    except Exception:
        return ""
