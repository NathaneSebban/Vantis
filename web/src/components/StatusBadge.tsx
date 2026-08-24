import type { ScanStatus } from "../api/types";

// Deep-violet family for the brand states; pink-free semantic colors elsewhere.
const META: Record<ScanStatus, { label: string; color: string; dot: boolean }> = {
  queued: { label: "Queued", color: "#64748b", dot: false },
  running: { label: "Running", color: "#4c2fbf", dot: true },
  completed: { label: "Completed", color: "#15803d", dot: false },
  failed: { label: "Failed", color: "#dc2626", dot: false },
  cancelled: { label: "Cancelled", color: "#e8590c", dot: false },
};

export function StatusBadge({ status }: { status: ScanStatus }) {
  const meta = META[status];
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold"
      style={{
        color: meta.color,
        background: `${meta.color}12`,
        boxShadow: `inset 0 0 0 1px ${meta.color}33`,
      }}
    >
      {meta.dot && (
        <span
          className="h-1.5 w-1.5 animate-pulseglow rounded-full"
          style={{ background: meta.color, boxShadow: `0 0 8px ${meta.color}` }}
        />
      )}
      {meta.label}
    </span>
  );
}
