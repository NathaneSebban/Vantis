import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { FindingCard } from "../components/FindingCard";
import { FindingDetail } from "../components/FindingDetail";
import { SeverityChart } from "../components/SeverityChart";
import { StatusBadge } from "../components/StatusBadge";
import { useFindings, useScan } from "../hooks/useScans";
import { api } from "../api/client";
import { SEVERITY_ORDER, type Finding, type Severity } from "../api/types";
import { SEVERITY_META } from "../components/severity";

const WEIGHT: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export function ScanReport() {
  const { id } = useParams<{ id: string }>();
  const { data: scan } = useScan(id);
  const { data: findings = [], isLoading } = useFindings(id);

  const [sevFilter, setSevFilter] = useState<Set<Severity>>(new Set());
  const [moduleFilter, setModuleFilter] = useState<string>("");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<Finding | null>(null);

  const modules = useMemo(() => Array.from(new Set(findings.map((f) => f.module))).sort(), [findings]);

  const visible = useMemo(() => {
    const q = search.trim().toLowerCase();
    return findings
      .filter((f) => (sevFilter.size ? sevFilter.has(f.severity) : true))
      .filter((f) => (moduleFilter ? f.module === moduleFilter : true))
      .filter((f) =>
        q
          ? f.title.toLowerCase().includes(q) ||
            f.description.toLowerCase().includes(q) ||
            f.matched_at.toLowerCase().includes(q)
          : true,
      )
      .sort((a, b) => WEIGHT[b.severity] - WEIGHT[a.severity]);
  }, [findings, sevFilter, moduleFilter, search]);

  function toggleSev(s: Severity) {
    setSevFilter((prev) => {
      const next = new Set(prev);
      next.has(s) ? next.delete(s) : next.add(s);
      return next;
    });
  }

  if (!id) return null;

  return (
    <div className="mx-auto max-w-4xl">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="font-mono text-xl text-zinc-100">{scan?.target ?? "…"}</h1>
          <div className="mt-2 flex items-center gap-3">
            {scan && <StatusBadge status={scan.status} />}
            <span className="text-sm text-zinc-500">{findings.length} findings</span>
            {scan?.status === "running" && (
              <Link to={`/scans/${id}`} className="text-sm text-blue-400 hover:underline">
                suivre en direct →
              </Link>
            )}
          </div>
        </div>
        <div className="flex gap-2">
          {(["json", "html", "md"] as const).map((fmt) => (
            <a
              key={fmt}
              href={api.reportUrl(id, fmt)}
              className="rounded-md border border-zinc-700 px-3 py-1.5 text-sm text-zinc-300 hover:bg-zinc-800"
            >
              {fmt.toUpperCase()}
            </a>
          ))}
        </div>
      </div>

      {/* Summary + chart */}
      {scan && (
        <div className="mt-6 grid gap-4 sm:grid-cols-2">
          <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-4">
            <h2 className="text-sm font-semibold text-zinc-300">Répartition par sévérité</h2>
            <div className="mt-3">
              <SeverityChart counts={scan.severity_counts} />
            </div>
          </div>
          <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-4">
            <h2 className="text-sm font-semibold text-zinc-300">Résumé</h2>
            <dl className="mt-3 grid grid-cols-5 gap-2 text-center">
              {SEVERITY_ORDER.map((s) => (
                <div key={s} className="rounded-md bg-zinc-950 p-2">
                  <dt className="text-xs" style={{ color: SEVERITY_META[s].hex }}>
                    {SEVERITY_META[s].label}
                  </dt>
                  <dd className="mt-0.5 text-lg font-semibold tabular-nums text-zinc-100">
                    {scan.severity_counts[s]}
                  </dd>
                </div>
              ))}
            </dl>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="mt-8 flex flex-wrap items-center gap-3">
        <div className="flex flex-wrap gap-1.5">
          {SEVERITY_ORDER.map((s) => {
            const on = sevFilter.has(s);
            return (
              <button
                key={s}
                onClick={() => toggleSev(s)}
                className={`rounded-full px-2.5 py-1 text-xs font-medium transition ${
                  on ? "text-white" : "bg-zinc-800 text-zinc-400 hover:bg-zinc-700"
                }`}
                style={on ? { background: SEVERITY_META[s].hex } : undefined}
              >
                {SEVERITY_META[s].label}
              </button>
            );
          })}
        </div>
        <select
          value={moduleFilter}
          onChange={(e) => setModuleFilter(e.target.value)}
          className="rounded-md border border-zinc-800 bg-zinc-900 px-2.5 py-1.5 text-sm text-zinc-300"
        >
          <option value="">Tous les modules</option>
          {modules.map((m) => (
            <option key={m} value={m}>
              {m}
            </option>
          ))}
        </select>
        <input
          type="search"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Rechercher…"
          className="flex-1 rounded-md border border-zinc-800 bg-zinc-900 px-3 py-1.5 text-sm text-zinc-100 outline-none focus:border-emerald-600"
        />
      </div>

      {/* Findings list */}
      <div className="mt-4 space-y-2">
        {isLoading && <p className="text-sm text-zinc-500">Chargement…</p>}
        {!isLoading && visible.length === 0 && (
          <p className="rounded-lg border border-dashed border-zinc-800 p-6 text-center text-sm text-zinc-600">
            Aucun finding ne correspond aux filtres.
          </p>
        )}
        {visible.map((f, i) => (
          <FindingCard key={`${f.module}-${f.timestamp}-${i}`} finding={f} onClick={() => setSelected(f)} />
        ))}
      </div>

      {selected && <FindingDetail finding={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
