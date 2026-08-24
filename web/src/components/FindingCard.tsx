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
      className={`card card-hover group flex w-full items-start gap-3 overflow-hidden p-3.5 text-left ${
        onClick ? "cursor-pointer" : "cursor-default"
      }`}
      style={{ borderLeft: `3px solid ${meta.hex}` }}
    >
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <SeverityBadge severity={finding.severity} />
          <span className="truncate font-semibold text-[#1c1940] group-hover:text-violetx-ink">{finding.title}</span>
        </div>
        <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-0.5 text-xs text-[#8b84a3]">
          <span className="rounded bg-violetx-soft px-1.5 py-0.5 font-mono text-violetx-deep">{finding.module}</span>
          <span className="truncate pt-0.5">{finding.matched_at || finding.target}</span>
        </div>
        {!compact && finding.description && (
          <p className="mt-2 line-clamp-2 text-sm text-[#635d80]">{finding.description}</p>
        )}
      </div>
    </button>
  );
}
