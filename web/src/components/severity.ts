// Single source of truth for severity presentation, shared by badges, cards
// and the chart. Pink-free, distinguishable, and legible on a white ground.

import type { Severity } from "../api/types";

export const SEVERITY_META: Record<
  Severity,
  { label: string; hex: string; glow: string; soft: string }
> = {
  critical: { label: "Critical", hex: "#a80f22", glow: "rgba(168,15,34,0.28)", soft: "rgba(168,15,34,0.08)" },
  high: { label: "High", hex: "#dc2626", glow: "rgba(220,38,38,0.26)", soft: "rgba(220,38,38,0.08)" },
  medium: { label: "Medium", hex: "#e8590c", glow: "rgba(232,89,12,0.26)", soft: "rgba(232,89,12,0.09)" },
  low: { label: "Low", hex: "#4f46e5", glow: "rgba(79,70,229,0.26)", soft: "rgba(79,70,229,0.08)" },
  info: { label: "Info", hex: "#64748b", glow: "rgba(100,116,139,0.22)", soft: "rgba(100,116,139,0.08)" },
};
