import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { StatusBadge } from "../components/StatusBadge";
import { useDeleteScan, useScanList } from "../hooks/useScans";
import { SEVERITY_ORDER, type ScanSummary } from "../api/types";
import { SEVERITY_META } from "../components/severity";

const PAGE = 20;

export function ScanHistory() {
  const navigate = useNavigate();
  const [offset, setOffset] = useState(0);
  const { data, isLoading } = useScanList(PAGE, offset);
  const del = useDeleteScan();

  function relaunch(scan: ScanSummary) {
    // Relaunch must still pass the authorization gate — prefill /new and let the
    // user re-confirm rather than silently re-submitting.
    navigate("/", { state: { target: scan.target, scope: scan.scope } });
  }

  return (
    <div className="mx-auto max-w-5xl">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-violetx-ink">Scan history</h1>
        <Link to="/" className="btn-primary">
          + New scan
        </Link>
      </div>

      <div className="mt-6 card overflow-hidden">
        <table className="w-full text-left text-sm">
          <thead className="bg-violetx-tint text-xs uppercase tracking-wide text-[#8b84a3]">
            <tr>
              <th className="px-4 py-3">Target</th>
              <th className="px-4 py-3">Date</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">Findings</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#eee9f8]">
            {isLoading && (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-[#8b84a3]">
                  Loading…
                </td>
              </tr>
            )}
            {data?.items.length === 0 && (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-[#8b84a3]">
                  No scans yet.
                </td>
              </tr>
            )}
            {data?.items.map((scan) => (
              <tr key={scan.scan_id} className="hover:bg-white">
                <td className="px-4 py-3">
                  <Link
                    to={scan.status === "running" || scan.status === "queued" ? `/scans/${scan.scan_id}` : `/scans/${scan.scan_id}/report`}
                    className="font-mono text-violetx-ink hover:text-violetx"
                  >
                    {scan.target}
                  </Link>
                  <div className="mt-0.5 text-xs text-[#9691ac]">{scan.modules.join(", ")}</div>
                </td>
                <td className="px-4 py-3 text-[#635d80]">{new Date(scan.created_at).toLocaleString()}</td>
                <td className="px-4 py-3">
                  <StatusBadge status={scan.status} />
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-1.5">
                    {SEVERITY_ORDER.filter((s) => scan.severity_counts[s] > 0).map((s) => (
                      <span
                        key={s}
                        title={SEVERITY_META[s].label}
                        className="inline-flex min-w-5 justify-center rounded px-1.5 text-xs font-semibold text-white"
                        style={{ background: SEVERITY_META[s].hex }}
                      >
                        {scan.severity_counts[s]}
                      </span>
                    ))}
                    {scan.findings_count === 0 && <span className="text-xs text-[#9691ac]">—</span>}
                  </div>
                </td>
                <td className="px-4 py-3">
                  <div className="flex justify-end gap-2">
                    <button onClick={() => relaunch(scan)} className="text-xs text-[#635d80] hover:text-violetx">
                      Relaunch
                    </button>
                    <button
                      onClick={() => {
                        if (confirm("Delete / cancel this scan?")) del.mutate(scan.scan_id);
                      }}
                      className="text-xs text-[#635d80] hover:text-red-600"
                    >
                      Delete
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {data && data.total > PAGE && (
        <div className="mt-4 flex items-center justify-between text-sm text-[#635d80]">
          <span>
            {offset + 1}–{Math.min(offset + PAGE, data.total)} of {data.total}
          </span>
          <div className="flex gap-2">
            <button
              disabled={offset === 0}
              onClick={() => setOffset(Math.max(0, offset - PAGE))}
              className="rounded border border-[#e6e1f5] px-3 py-1 disabled:opacity-40"
            >
              Previous
            </button>
            <button
              disabled={offset + PAGE >= data.total}
              onClick={() => setOffset(offset + PAGE)}
              className="rounded border border-[#e6e1f5] px-3 py-1 disabled:opacity-40"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
