// Typed API client. All calls go through one fetch wrapper so error handling
// and the base URL live in a single place.
//
// Base URL: relative by default (the Vite dev proxy and the production reverse
// proxy both route /api to the backend). Override with VITE_API_BASE when the
// backend lives on a different origin.

import type {
  Finding,
  ScanCreate,
  ScanCreatedResponse,
  ScanDetail,
  ScanListResponse,
  Severity,
} from "./types";

const BASE = (import.meta.env.VITE_API_BASE ?? "").replace(/\/$/, "");
// Optional API key, sent only when the backend has auth enabled. Left unset in
// local dev (auth disabled server-side).
const API_KEY = import.meta.env.VITE_API_KEY ?? "";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(API_KEY ? { "X-API-Key": API_KEY } : {}),
      ...(init?.headers ?? {}),
    },
    ...init,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, detail);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export const api = {
  createScan(payload: ScanCreate): Promise<ScanCreatedResponse> {
    return request("/api/scans", { method: "POST", body: JSON.stringify(payload) });
  },

  listScans(limit = 20, offset = 0): Promise<ScanListResponse> {
    return request(`/api/scans?limit=${limit}&offset=${offset}`);
  },

  getScan(id: string): Promise<ScanDetail> {
    return request(`/api/scans/${id}`);
  },

  getFindings(id: string, filters?: { severity?: Severity[]; module?: string[] }): Promise<Finding[]> {
    const qs = new URLSearchParams();
    if (filters?.severity?.length) qs.set("severity", filters.severity.join(","));
    if (filters?.module?.length) qs.set("module", filters.module.join(","));
    const suffix = qs.toString() ? `?${qs.toString()}` : "";
    return request(`/api/scans/${id}/findings${suffix}`);
  },

  deleteScan(id: string): Promise<{ scan_id: string; action: string }> {
    return request(`/api/scans/${id}`, { method: "DELETE" });
  },

  reportUrl(id: string, format: "json" | "html" | "md" | "pdf"): string {
    return `${BASE}/api/scans/${id}/report?format=${format}`;
  },

  // Build the ws:// URL for the live stream from the current origin (or the
  // configured API base).
  liveSocketUrl(id: string): string {
    // Browsers can't set headers on a WebSocket handshake, so the key (when
    // configured) travels as a query parameter.
    const query = API_KEY ? `?key=${encodeURIComponent(API_KEY)}` : "";
    if (BASE) {
      const url = new URL(BASE);
      url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
      return `${url.origin}/api/scans/${id}/live${query}`;
    }
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    return `${proto}//${window.location.host}/api/scans/${id}/live${query}`;
  },
};
