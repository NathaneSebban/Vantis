import type { Finding } from "../api/types";
import { SeverityBadge } from "./SeverityBadge";

// Side panel showing the full detail of a finding.
export function FindingDetail({ finding, onClose }: { finding: Finding; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-violetx-ink/25 backdrop-blur-sm" onClick={onClose}>
      <aside
        className="h-full w-full max-w-md overflow-y-auto border-l border-[#e6e1f5] bg-white p-6 shadow-[-24px_0_60px_-24px_rgba(76,47,191,0.4)]"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <SeverityBadge severity={finding.severity} />
              <span className="rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-[#9691ac] ring-1 ring-[#e6e1f5]">
                {finding.confidence} confidence
              </span>
            </div>
            <h2 className="mt-2 text-lg font-bold text-violetx-ink">{finding.title}</h2>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-1.5 text-[#9691ac] transition hover:bg-violetx-soft hover:text-violetx-ink"
            aria-label="Close"
          >
            ✕
          </button>
        </div>

        <dl className="mt-6 space-y-4 text-sm">
          <Field label="Module" value={finding.module} mono />
          {(finding.owasp || finding.cwe) && (
            <Field label="Classification" value={[finding.owasp, finding.cwe].filter(Boolean).join(" · ")} mono />
          )}
          <Field label="Location" value={finding.matched_at || finding.target} mono />
          {finding.description && <Field label="Description" value={finding.description} />}
          {finding.evidence && <Field label="Evidence" value={finding.evidence} mono block />}
          {finding.remediation && <Field label="Remediation" value={finding.remediation} />}
          {finding.references.length > 0 && (
            <div>
              <dt className="text-xs font-semibold uppercase tracking-wide text-[#9691ac]">References</dt>
              <dd className="mt-1 space-y-1">
                {finding.references.map((ref) => (
                  <a
                    key={ref}
                    href={ref}
                    target="_blank"
                    rel="noreferrer"
                    className="block truncate font-medium text-violetx hover:underline"
                  >
                    {ref}
                  </a>
                ))}
              </dd>
            </div>
          )}
          {finding.timestamp && <Field label="Detected at" value={finding.timestamp} mono />}
        </dl>
      </aside>
    </div>
  );
}

function Field({ label, value, mono, block }: { label: string; value: string; mono?: boolean; block?: boolean }) {
  return (
    <div>
      <dt className="text-xs font-semibold uppercase tracking-wide text-[#9691ac]">{label}</dt>
      <dd
        className={`mt-1 text-[#2b2740] ${mono ? "font-mono text-xs" : ""} ${
          block ? "whitespace-pre-wrap break-all rounded-lg bg-violetx-tint p-2 ring-1 ring-[#eae5f8]" : ""
        }`}
      >
        {value}
      </dd>
    </div>
  );
}
