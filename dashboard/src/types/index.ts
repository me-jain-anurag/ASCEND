// ─── Network ─────────────────────────────────────────────────────────────────
export interface Account { username: string; type: string; privilege_level: number; }
export interface Vector {
  vector_id: string; technique: string; technique_name?: string;
  cve: string | null; cvss: number;
  features: Record<string, unknown>; verified_exploitable: boolean | null;
}
export interface Host {
  hostname: string; role: string; os: string; kernel_version: string;
  asset_value: number; is_entry_point: boolean; is_crown_jewel: boolean;
  accounts: Account[]; vectors: Vector[];
}
export interface ReachabilityEdge { from_host: string; to_host: string; port: number; service: string; }
export interface NetworkData { hosts: Host[]; reachability: ReachabilityEdge[]; }

// ─── Paths ────────────────────────────────────────────────────────────────────
export interface Credential { cred_id: string; type: string; discoverable_at: string; }
export interface PathStep {
  step_number: number; source_host: string; target_host: string;
  source_account: Account; target_account: Account;
  vector: Vector; credential: Credential | null;
  description: string; verified: boolean | null;
}
export interface AttackPath {
  path_id: string; name: string; length: number;
  entry_host: string; crown_jewel_host: string;
  overall_verified: boolean | null; risk_score?: number; steps: PathStep[];
}
export interface PathsResponse {
  scenario: string; name: string; entry_point: string; crown_jewel: string;
  total_paths: number; paths: AttackPath[]; description: string;
}

// ─── Verify ───────────────────────────────────────────────────────────────────
export interface VerifyEvidence { technique: string; exit_code: number; stdout: string; telemetry: string; }
export interface VerifyStep { step_number: number; verified: boolean; evidence: VerifyEvidence; }
export interface VerifyPathResult { overall_verified: boolean; failed_at_step?: number; steps: VerifyStep[]; }
export interface VerifyData {
  execution_run_id: string; status: string; timestamp: string;
  summary: { paths_tested: number; paths_verified: number; paths_failed: number; precision?: number; };
  results: Record<string, VerifyPathResult>;
}

// ─── Remediation ──────────────────────────────────────────────────────────────
export interface Fix {
  fix_id: string; rank: number; title: string; chokepoint_type: string;
  target_host: string; target_vector: string; technique_broken: string;
  cost: number; description: string; paths_eliminated: string[];
  efficacy_percentage: number; is_recommended_chokepoint: boolean;
}
export interface EfficacyPoint { fixes_applied: number; paths_remaining: number; paths_eliminated: number; reduction_pct: number; }
export interface RemediationData { total_verified_paths: number; ranked_fixes: Fix[]; efficacy_curve: EfficacyPoint[]; }

// ─── Status ───────────────────────────────────────────────────────────────────
export interface StatusMetrics {
  hosts_count: number; vectors_count: number; enumerated_paths: number;
  verified_paths: number; precision?: string; chokepoints_identified: number;
  active_scenario: string; applied_fixes_count?: number; eliminated_paths_count?: number;
}
export interface StatusData {
  system: string; version: string; status: string; lab_environment: string;
  summary_metrics: StatusMetrics;
}
