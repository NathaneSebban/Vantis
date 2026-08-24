import type { ScanStatus } from "../api/types";

const META: Record<ScanStatus, { label: string; color: string; dot: boolean }> = {
  queued: { label: "Queued", color: "#8b8299", dot: false },
  running: { label: "Running", color: "#22d3ee", dot: true },
  completed: { label: "Completed", color: "#a855f7", dot: false },
  failed: { label: "Failed", color: "#ff2d55", dot: false },
  cancelled: { label: "Cancelled", color: "#ff9f43", dot: false },
};

export function StatusBadge({ status }: { status: ScanStatus }) {
  const meta = META[status];
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold"
      style={{
        color: meta.color,
        background: `${meta.color}14`,
        boxShadow: `inset 0 0 0 1px ${meta.color}44`,
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
