"""Assessment-mode scanner importers (Trivy JSON + Lynis audit reports).

Implements docs/10 section 5 (Scanner Integration):
- Ingests existing scanner outputs (Trivy vulnerability JSON, Lynis host audit
  findings) into the exact ``environment_graph/facts.json`` schema so the
  mode-agnostic enumerator and chokepoint engine can run read-only in
  Assessment mode without ever executing exploits.
- Non-negotiable provenance rule: every imported vector is tagged
  ``provenance="declared"``, ``source_tool="trivy"|"lynis"``, and
  ``verified_exploitable=None``.
"""

from __future__ import annotations

from typing import Any


def _extract_trivy_cvss(vuln: dict[str, Any]) -> float | None:
    cvss_block = vuln.get("CVSS") or {}
    for src in ("nvd", "redhat", "ghsa"):
        entry = cvss_block.get(src) or {}
        if entry.get("V3Score") is not None:
            return float(entry["V3Score"])
    for entry in cvss_block.values():
        if isinstance(entry, dict) and entry.get("V3Score") is not None:
            return float(entry["V3Score"])
    sev_map = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.5, "LOW": 3.0}
    return sev_map.get(str(vuln.get("Severity", "")).upper())


def import_trivy_json(
    trivy_report: dict[str, Any],
    *,
    hostname: str,
    knowledge_pack: dict[str, Any],
) -> list[dict[str, Any]]:
    """Map Trivy JSON vulnerability entries on *hostname* into ASCEND vectors.

    Only CVEs mapped to an in-scope ATT&CK technique in ``knowledge_pack`` are
    imported; out-of-scope findings are ignored to preserve ASCEND's locked scope.
    """
    cves_kg = knowledge_pack.get("cves") or {}
    techs_kg = knowledge_pack.get("techniques") or {}
    vectors: list[dict[str, Any]] = []
    seen_cves: set[str] = set()

    for result in trivy_report.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            cve_id = vuln.get("VulnerabilityID")
            if not cve_id or cve_id in seen_cves or cve_id not in cves_kg:
                continue
            seen_cves.add(cve_id)
            kg_entry = cves_kg[cve_id]
            attack_id = kg_entry.get("attack_id", "T1068")
            tech_name = (techs_kg.get(attack_id) or {}).get("name", attack_id)
            cvss = _extract_trivy_cvss(vuln)
            if cvss is None:
                cvss = kg_entry.get("base_cvss", 7.5)

            vectors.append({
                "vector_id": f"v_{hostname}_trivy_{cve_id.lower().replace('-', '_')}",
                "host": hostname,
                "technique": attack_id,
                "technique_name": tech_name,
                "cve": cve_id,
                "cvss": cvss,
                "kind": "privilege_escalation_local",
                "requires": {"host": hostname, "privilege": "low"},
                "gains": {"host": hostname, "privilege": "root"},
                "config_exploitable": True,
                "verified_exploitable": None,
                "features": {
                    "provenance": "declared",
                    "source_tool": "trivy",
                    "package": vuln.get("PkgName", ""),
                    "installed_version": vuln.get("InstalledVersion", ""),
                    "fixed_version": vuln.get("FixedVersion", ""),
                },
            })
    return vectors


def import_lynis_audit(
    lynis_data: dict[str, Any],
    *,
    hostname: str,
    scope: dict[str, Any],
    knowledge_pack: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Map structured Lynis host audit findings into ASCEND vectors + skipped controls.

    Accepts a dict with optional keys: ``sudo_rules`` (list of ``{user, binary, nopasswd, noexec}``),
    ``suid_binaries`` (list of ``{path, nosuid_mount}``), and ``readable_keys`` (list of ``{path, mode}``).
    Applies the same shell-escape allowlist from ``scope.yaml`` so decoys are declined.
    """
    rules = scope.get("rules") or {}
    sudo_escapes = set((rules.get("sudo") or {}).get("shell_escape_binaries") or ["/bin/tar", "/usr/bin/find", "/usr/bin/vim"])
    suid_escapes = set((rules.get("suid") or {}).get("shell_escape_binaries") or ["/usr/bin/find", "/usr/bin/python3", "/usr/bin/vim"])
    techs_kg = knowledge_pack.get("techniques") or {}

    vectors: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []

    for rule in lynis_data.get("sudo_rules") or []:
        binary = rule.get("binary", "")
        if not rule.get("nopasswd", False):
            skipped.append({"host": hostname, "technique": "T1548.003", "rule": binary, "reason": "requires password"})
            continue
        if binary not in sudo_escapes:
            skipped.append({"host": hostname, "technique": "T1548.003", "rule": f"NOPASSWD: {binary}", "reason": f"{binary} has no documented shell escape"})
            continue
        vectors.append({
            "vector_id": f"v_{hostname}_lynis_sudo_{binary.split('/')[-1]}",
            "host": hostname,
            "technique": "T1548.003",
            "technique_name": (techs_kg.get("T1548.003") or {}).get("name", "Sudo and Sudo Caching"),
            "cve": None,
            "cvss": 7.8,
            "kind": "privilege_escalation_local",
            "requires": {"host": hostname, "privilege": "low"},
            "gains": {"host": hostname, "privilege": "root"},
            "config_exploitable": True,
            "verified_exploitable": None,
            "features": {
                "provenance": "declared",
                "source_tool": "lynis",
                "sudo_noexec": bool(rule.get("noexec", False)),
                "binary": binary,
            },
        })

    for suid in lynis_data.get("suid_binaries") or []:
        path = suid.get("path", "")
        if path not in suid_escapes:
            skipped.append({"host": hostname, "technique": "T1548.001", "path": path, "reason": f"{path} not in shell-escape list"})
            continue
        vectors.append({
            "vector_id": f"v_{hostname}_lynis_suid_{path.split('/')[-1]}",
            "host": hostname,
            "technique": "T1548.001",
            "technique_name": (techs_kg.get("T1548.001") or {}).get("name", "Setuid and Setgid"),
            "cve": None,
            "cvss": 7.8,
            "kind": "privilege_escalation_local",
            "requires": {"host": hostname, "privilege": "low"},
            "gains": {"host": hostname, "privilege": "root"},
            "config_exploitable": True,
            "verified_exploitable": None,
            "features": {
                "provenance": "declared",
                "source_tool": "lynis",
                "nosuid_mount": bool(suid.get("nosuid_mount", False)),
                "suid_path": path,
            },
        })

    for key in lynis_data.get("readable_keys") or []:
        mode = str(key.get("mode", "0600"))
        path = key.get("path", "")
        if mode.endswith("00"):
            skipped.append({"host": hostname, "technique": "T1552.001", "path": path, "reason": f"mode {mode} — owner-only"})
            continue
        vectors.append({
            "vector_id": f"v_{hostname}_lynis_key_{path.split('/')[-1]}",
            "host": hostname,
            "technique": "T1552.001",
            "technique_name": (techs_kg.get("T1552.001") or {}).get("name", "Credentials In Files"),
            "cve": None,
            "cvss": 5.5,
            "kind": "credential_access",
            "reads_credential": "app_deploy_key",
            "requires": {"host": hostname, "privilege": "low"},
            "config_exploitable": True,
            "verified_exploitable": None,
            "features": {
                "provenance": "declared",
                "source_tool": "lynis",
                "mode": mode,
                "path": path,
            },
        })

    return vectors, skipped


def build_assessment_facts(
    *,
    hosts: list[dict[str, Any]],
    accounts: list[dict[str, Any]],
    reachability: list[dict[str, Any]],
    credentials: list[dict[str, Any]],
    vectors: list[dict[str, Any]],
    entry: dict[str, Any],
    crown_jewel: dict[str, Any],
    source_label: str = "assessment:trivy+lynis",
) -> dict[str, Any]:
    """Assemble an Assessment-mode ``facts.json`` payload (read-only, zero execution)."""
    return {
        "_meta": {
            "source": source_label,
            "mode": "assessment",
            "execution_verified": False,
        },
        "entry": entry,
        "crown_jewel": crown_jewel,
        "hosts": hosts,
        "accounts": accounts,
        "reachability": reachability,
        "credentials": credentials,
        "vectors": vectors,
    }
