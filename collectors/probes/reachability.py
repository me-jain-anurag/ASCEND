"""Probe: who can actually reach whom.

This is the one probe that is not a local file read. For every ordered pair of
hosts it opens a real TCP connection *from inside the source host* to each port
the target is listening on, by DNS name and by every address the target holds.

Doing it this way is the difference between an environment graph that describes
the network and one that asserts it. The lab puts web01 and db01 on separate
bridges; nothing tells the collector that. It finds out because the connection
fails, and it records why it failed as evidence.

The prober runs with python3 (already required on every lab host) rather than nc
or nmap, so no scanning tool has to be installed on the targets.
"""

from __future__ import annotations

import json

# Executed inside the SOURCE host. argv: <timeout> <port> <endpoint>...
_PROBE = r"""
import json, socket, sys
timeout = float(sys.argv[1]); port = int(sys.argv[2]); out = []
for endpoint in sys.argv[3:]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((endpoint, port))
        out.append({"endpoint": endpoint, "result": "open"})
    except socket.gaierror as e:
        out.append({"endpoint": endpoint, "result": "dns_failure", "detail": str(e)})
    except (socket.timeout, TimeoutError):
        out.append({"endpoint": endpoint, "result": "filtered", "detail": "timeout"})
    except OSError as e:
        out.append({"endpoint": endpoint, "result": "refused",
                    "detail": e.strerror or str(e)})
    finally:
        s.close()
print(json.dumps(out))
"""


def host_addresses(host: str, tp) -> list[str]:
    """Every global IPv4 address the host holds, one per attached network."""
    res = tp.run(host, ["ip", "-4", "-o", "addr", "show", "scope", "global"])
    addrs = []
    for line in res.stdout.splitlines():
        fields = line.split()
        if "inet" in fields:
            cidr = fields[fields.index("inet") + 1]
            addrs.append(cidr.split("/")[0])
    return addrs


def collect_matrix(hosts: list[str], tp, listening: dict[str, list[dict]],
                   timeout: float = 1.5) -> list[dict]:
    """Full source x target x port sweep. Returns one record per attempt."""
    addresses = {h: host_addresses(h, tp) for h in hosts}
    results = []

    for src in hosts:
        for dst in hosts:
            if src == dst:
                continue
            for entry in listening.get(dst, []):
                # Loopback-bound listeners are unreachable from another host by
                # construction; probing them only buys a timeout per attempt.
                if entry.get("loopback"):
                    continue
                port = entry["port"]
                endpoints = [dst, *addresses.get(dst, [])]
                res = tp.run(
                    src,
                    ["python3", "-c", _PROBE, str(timeout), str(port), *endpoints],
                    timeout=int(timeout * len(endpoints)) + 15,
                )
                if not res.ok:
                    results.append({
                        "from": src, "to": dst, "port": port,
                        "service": entry.get("service", "unknown"),
                        "reachable": False,
                        "evidence": [{"endpoint": dst, "result": "probe_error",
                                      "detail": res.stderr.strip()[:200]}],
                    })
                    continue
                try:
                    attempts = json.loads(res.stdout.strip().splitlines()[-1])
                except (ValueError, IndexError):
                    attempts = []
                results.append({
                    "from": src, "to": dst, "port": port,
                    "service": entry.get("service", "unknown"),
                    # Reachable if ANY endpoint answered. A name that does not
                    # resolve but an address that connects is still reachability.
                    "reachable": any(a.get("result") == "open" for a in attempts),
                    "evidence": attempts,
                })
    return results
