// Subscribes to /api/scans/{id}/live and accumulates the streamed events into
// React state: findings as they arrive, live progress, and the current status.
//
// Robust to reconnects and to scans that already finished: the caller should
// also poll the REST status (useScan) as a fallback, but this hook gives the
// real-time feel described in the spec.

import { useEffect, useRef, useState } from "react";
import { api } from "../api/client";
import type { Finding, LiveEvent, ScanStatus } from "../api/types";

export interface LiveState {
  connected: boolean;
  status: ScanStatus | null;
  currentModule: string | null;
  modulesDone: number;
  modulesTotal: number;
  findings: Finding[];
  error: string | null;
}

const TERMINAL: ScanStatus[] = ["completed", "failed", "cancelled"];

export function useScanWebSocket(scanId: string | undefined, enabled = true): LiveState {
  const [state, setState] = useState<LiveState>({
    connected: false,
    status: null,
    currentModule: null,
    modulesDone: 0,
    modulesTotal: 0,
    findings: [],
    error: null,
  });
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    if (!scanId || !enabled) return;

    const ws = new WebSocket(api.liveSocketUrl(scanId));
    wsRef.current = ws;

    ws.onopen = () => setState((s) => ({ ...s, connected: true }));
    ws.onclose = () => setState((s) => ({ ...s, connected: false }));
    ws.onerror = () => setState((s) => ({ ...s, connected: false }));

    ws.onmessage = (ev) => {
      let event: LiveEvent;
      try {
        event = JSON.parse(ev.data);
      } catch {
        return;
      }
      setState((s) => {
        switch (event.type) {
          case "status":
            return { ...s, status: event.status, error: event.error ?? s.error };
          case "module_start":
            return { ...s, currentModule: event.module, modulesTotal: event.total };
          case "module_end":
            return { ...s, modulesDone: event.index, modulesTotal: event.total };
          case "finding":
            return { ...s, findings: [event.finding, ...s.findings] };
          case "scan_end":
            return { ...s, currentModule: null };
          default:
            return s;
        }
      });
    };

    return () => {
      wsRef.current = null;
      ws.close();
    };
  }, [scanId, enabled]);

  return state;
}

export function isTerminal(status: ScanStatus | null): boolean {
  return status != null && TERMINAL.includes(status);
}
