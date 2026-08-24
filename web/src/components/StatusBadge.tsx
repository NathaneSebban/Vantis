import type { ScanStatus } from "../api/types";

const META: Record<ScanStatus, { label: string; className: string }> = {
  queued: { label: "En file", className: "bg-zinc-700 text-zinc-200" },
  running: { label: "En cours", className: "bg-blue-600/80 text-white" },
  completed: { label: "Terminé", className: "bg-emerald-700 text-white" },
  failed: { label: "Échec", className: "bg-red-800 text-white" },
  cancelled: { label: "Annulé", className: "bg-amber-800 text-white" },
};

export function StatusBadge({ status }: { status: ScanStatus }) {
  const meta = META[status];
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ${meta.className}`}>
      {status === "running" && <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-white" />}
      {meta.label}
    </span>
  );
}
