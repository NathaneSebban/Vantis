// Single source of truth for severity presentation, shared by badges, cards
// and the chart so colors stay consistent everywhere.

import type { Severity } from "../api/types";

export const SEVERITY_META: Record<
  Severity,
  { label: string; hex: string; badge: string; text: string }
> = {
  critical: { label: "Critical", hex: "#991b1b", badge: "bg-severity-critical text-white", text: "text-red-400" },
  high: { label: "High", hex: "#dc2626", badge: "bg-severity-high text-white", text: "text-red-400" },
  medium: { label: "Medium", hex: "#ea580c", badge: "bg-severity-medium text-white", text: "text-orange-400" },
  low: { label: "Low", hex: "#2563eb", badge: "bg-severity-low text-white", text: "text-blue-400" },
  info: { label: "Info", hex: "#6b7280", badge: "bg-severity-info text-white", text: "text-zinc-400" },
};
