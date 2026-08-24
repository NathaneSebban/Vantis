// Single source of truth for severity presentation, shared by badges, cards
// and the chart so colors stay consistent everywhere. Bright, neon-leaning
// hues that glow on the near-black ground.

import type { Severity } from "../api/types";

export const SEVERITY_META: Record<
  Severity,
  { label: string; hex: string; glow: string; text: string }
> = {
  critical: { label: "Critical", hex: "#ff2d55", glow: "rgba(255,45,85,0.55)", text: "text-[#ff6b86]" },
  high: { label: "High", hex: "#ff5470", glow: "rgba(255,84,112,0.5)", text: "text-[#ff7d93]" },
  medium: { label: "Medium", hex: "#ff9f43", glow: "rgba(255,159,67,0.5)", text: "text-[#ffb366]" },
  low: { label: "Low", hex: "#3b82f6", glow: "rgba(59,130,246,0.5)", text: "text-[#6ba3ff]" },
  info: { label: "Info", hex: "#8b8299", glow: "rgba(139,130,153,0.4)", text: "text-[#a79fb8]" },
};
