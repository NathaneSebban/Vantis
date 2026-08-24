import type { Finding } from "../api/types";
import { SEVERITY_META } from "./severity";
import { SeverityBadge } from "./SeverityBadge";

interface Props {
  finding: Finding;
  onClick?: () => void;
  compact?: boolean;
}

// A single finding row. In the live feed it renders compactly; elsewhere it is
// clickable to open the detail panel.
export function FindingCard({ finding, onClick, compact }: Props) {
  const meta = SEVERITY_META[finding.severity];
  return (
    <button
      type="button"
      onClick={onClick}
      className={`flex w-full items-start gap-3 rounded-lg border border-zinc-800 bg-zinc-900/60 p-3 text-left transition hover:border-zinc-700 hover:bg-zinc-900 ${
        onClick ? "cursor-pointer" : "cursor-default"
      }`}
      style={{ borderLeft: `3px solid ${meta.hex}` }}
    >
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <SeverityBadge severity={finding.severity} />
          <span className="truncate font-medium text-zinc-100">{finding.title}</span>
        </div>
        <div className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5 text-xs text-zinc-500">
          <span className="font-mono">{finding.module}</span>
          <span className="truncate">{finding.matched_at || finding.target}</span>
        </div>
        {!compact && finding.description && (
          <p className="mt-1.5 line-clamp-2 text-sm text-zinc-400">{finding.description}</p>
        )}
      </div>
    </button>
  );
}
