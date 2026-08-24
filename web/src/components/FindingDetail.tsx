import type { Finding } from "../api/types";
import { SEVERITY_META } from "./severity";
import { SeverityBadge } from "./SeverityBadge";

// Side panel showing the full detail of a finding.
export function FindingDetail({ finding, onClose }: { finding: Finding; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-black/50" onClick={onClose}>
      <aside
        className="h-full w-full max-w-md overflow-y-auto border-l border-zinc-800 bg-zinc-950 p-6"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between gap-4">
          <div>
            <SeverityBadge severity={finding.severity} />
            <h2 className="mt-2 text-lg font-semibold text-zinc-100">{finding.title}</h2>
          </div>
          <button
            onClick={onClose}
            className="rounded p-1 text-zinc-500 hover:bg-zinc-800 hover:text-zinc-200"
            aria-label="Fermer"
          >
            ✕
          </button>
        </div>

        <dl className="mt-6 space-y-4 text-sm">
          <Field label="Module" value={finding.module} mono />
          <Field label="Emplacement" value={finding.matched_at || finding.target} mono />
          {finding.description && <Field label="Description" value={finding.description} />}
          {finding.evidence && <Field label="Preuve" value={finding.evidence} mono block />}
          {finding.remediation && <Field label="Remédiation" value={finding.remediation} />}
          {finding.references.length > 0 && (
            <div>
              <dt className="text-xs font-semibold uppercase tracking-wide text-zinc-500">Références</dt>
              <dd className="mt-1 space-y-1">
                {finding.references.map((ref) => (
                  <a
                    key={ref}
                    href={ref}
                    target="_blank"
                    rel="noreferrer"
                    className="block truncate text-blue-400 hover:underline"
                    style={{ color: SEVERITY_META[finding.severity].hex }}
                  >
                    {ref}
                  </a>
                ))}
              </dd>
            </div>
          )}
          {finding.timestamp && <Field label="Détecté à" value={finding.timestamp} mono />}
        </dl>
      </aside>
    </div>
  );
}

function Field({ label, value, mono, block }: { label: string; value: string; mono?: boolean; block?: boolean }) {
  return (
    <div>
      <dt className="text-xs font-semibold uppercase tracking-wide text-zinc-500">{label}</dt>
      <dd
        className={`mt-1 text-zinc-200 ${mono ? "font-mono text-xs" : ""} ${
          block ? "whitespace-pre-wrap break-all rounded bg-zinc-900 p-2" : ""
        }`}
      >
        {value}
      </dd>
    </div>
  );
}
