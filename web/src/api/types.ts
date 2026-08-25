// Types mirroring the backend Pydantic schemas (api/schemas.py). Kept in sync
// by hand — the shapes are small and stable.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type ScanStatus =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

export const MODULE_CATEGORIES = ["recon", "web", "cve"] as const;
export type ModuleCategory = (typeof MODULE_CATEGORIES)[number];

export type Confidence = "low" | "medium" | "high";

export interface Finding {
  module: string;
  title: string;
  severity: Severity;
  target: string;
  description: string;
  evidence: string;
  remediation: string;
  references: string[];
  matched_at: string;
  timestamp: string;
  confidence: Confidence;
  owasp: string;
  cwe: string;
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ScanSummary {
  scan_id: string;
  target: string;
  scope: string[];
  modules: string[];
  status: ScanStatus;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  findings_count: number;
  severity_counts: SeverityCounts;
}

export interface ScanDetail extends ScanSummary {
  current_module: string;
  modules_done: number;
  modules_total: number;
  error: string;
}

export interface ScanListResponse {
  total: number;
  limit: number;
  offset: number;
  items: ScanSummary[];
}

export interface TrendPoint {
  scan_id: string;
  created_at: string;
  severity_counts: SeverityCounts;
  findings_count: number;
}

export interface TrendResponse {
  target: string;
  points: TrendPoint[];
}

export interface ScanCreate {
  target: string;
  scope: string[];
  modules: ModuleCategory[];
  module_names?: string[];
  // Automated form-based login: instead of already having a session cookie,
  // Vantis submits the target's own login form itself with these credentials.
  // In-memory only on the backend, never persisted.
  login_url?: string;
  login_username?: string;
  login_password?: string;
  // Render the target in headless Chromium to discover JS-rendered content
  // and real XHR/fetch API calls.
  browser_crawl?: boolean;
  // A second authenticated identity, for IDOR testing (idor-check compares
  // what this identity can access against the primary identity's resources).
  secondary_headers?: Record<string, string>;
  secondary_cookies?: Record<string, string>;
  authorized: boolean;
}

export interface ModuleInfo {
  name: string;
  category: ModuleCategory;
  description: string;
}

export interface ScanCreatedResponse {
  scan_id: string;
  status: ScanStatus;
}

// WebSocket event envelope pushed by the backend on /api/scans/{id}/live.
export type LiveEvent =
  | { type: "status"; status: ScanStatus; error?: string }
  | { type: "module_start"; module: string; category: string; index: number; total: number }
  | { type: "module_end"; module: string; count: number; index: number; done?: number; total: number }
  | { type: "finding"; finding: Finding }
  | { type: "scan_end"; total_findings: number };

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
