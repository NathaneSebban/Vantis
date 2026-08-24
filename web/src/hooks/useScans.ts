// react-query wrappers around the API. Components use these instead of calling
// the client directly, so caching, polling and invalidation are centralized.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import type { ScanCreate, ScanStatus, Severity } from "../api/types";

const ACTIVE: ScanStatus[] = ["queued", "running"];

export function useScanList(limit = 20, offset = 0) {
  return useQuery({
    queryKey: ["scans", limit, offset],
    queryFn: () => api.listScans(limit, offset),
    refetchInterval: 5000, // keep the history fresh while scans run
  });
}

export function useScan(id: string | undefined) {
  return useQuery({
    queryKey: ["scan", id],
    queryFn: () => api.getScan(id!),
    enabled: !!id,
    // Poll while the scan is active; stop once it reaches a terminal state.
    refetchInterval: (query) =>
      query.state.data && ACTIVE.includes(query.state.data.status) ? 1500 : false,
  });
}

export function useFindings(
  id: string | undefined,
  filters?: { severity?: Severity[]; module?: string[] },
  enabled = true,
) {
  return useQuery({
    queryKey: ["findings", id, filters],
    queryFn: () => api.getFindings(id!, filters),
    enabled: !!id && enabled,
  });
}

export function useCreateScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: ScanCreate) => api.createScan(payload),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scans"] }),
  });
}

export function useDeleteScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.deleteScan(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scans"] }),
  });
}
