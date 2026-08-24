import type { Severity } from "../api/types";
import { SEVERITY_META } from "./severity";

export function SeverityBadge({ severity }: { severity: Severity }) {
  const meta = SEVERITY_META[severity];
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider"
      style={{
        color: meta.hex,
        background: meta.soft,
        boxShadow: `inset 0 0 0 1px ${meta.hex}33`,
      }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: meta.hex, boxShadow: `0 0 6px ${meta.glow}` }} />
      {meta.label}
    </span>
  );
}
