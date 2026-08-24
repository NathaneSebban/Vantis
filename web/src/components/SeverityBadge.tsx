import type { Severity } from "../api/types";
import { SEVERITY_META } from "./severity";

export function SeverityBadge({ severity }: { severity: Severity }) {
  const meta = SEVERITY_META[severity];
  return (
    <span
      className={`inline-block rounded px-2 py-0.5 text-xs font-semibold uppercase tracking-wide ${meta.badge}`}
    >
      {meta.label}
    </span>
  );
}
