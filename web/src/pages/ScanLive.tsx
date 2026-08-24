import { useMemo } from "react";
import { Link, useParams } from "react-router-dom";
import { FindingCard } from "../components/FindingCard";
import { ProgressBar } from "../components/ProgressBar";
import { StatusBadge } from "../components/StatusBadge";
import { useScan } from "../hooks/useScans";
import { isTerminal, useScanWebSocket } from "../hooks/useScanWebSocket";
import { SEVERITY_ORDER, type ScanStatus } from "../api/types";
import { SEVERITY_META } from "../components/severity";

export function ScanLive() {
  const { id } = useParams<{ id: string }>();
  const { data: scan } = useScan(id);
  const live = useScanWebSocket(id);

  // Status/progress: prefer live values, fall back to the polled REST record so
  // the page is correct even if the socket dropped or the scan already ended.
  const status: ScanStatus | null = live.status ?? scan?.status ?? null;
  const currentModule = live.currentModule ?? (scan?.status === "running" ? scan.current_module : null);
  const modulesDone = Math.max(live.modulesDone, scan?.modules_done ?? 0);
  const modulesTotal = Math.max(live.modulesTotal, scan?.modules_total ?? 0);
  const done = isTerminal(status);

  // Live findings from the socket; if we joined late, fall back to the count.
  const findings = live.findings;
  const findingsCount = findings.length || scan?.findings_count || 0;

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const f of findings) c[f.severity] = (c[f.severity] ?? 0) + 1;
    return c;
  }, [findings]);

  if (!id) return null;

  return (
    <div className="mx-auto max-w-3xl">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="font-mono text-xl text-zinc-100">{scan?.target ?? "…"}</h1>
          <div className="mt-2 flex items-center gap-2">
            {status && <StatusBadge status={status} />}
            <span className="text-xs text-zinc-500">
              {live.connected ? "● flux temps réel" : "○ hors ligne (polling)"}
            </span>
          </div>
        </div>
        {done && (
          <Link
            to={`/scans/${id}/report`}
            className="rounded-md bg-emerald-600 px-4 py-2 text-sm font-semibold text-white hover:bg-emerald-500"
          >
            Voir le rapport →
          </Link>
        )}
      </div>

      {/* Progress */}
      <div className="mt-6 rounded-lg border border-zinc-800 bg-zinc-900/40 p-4">
        <div className="flex items-center justify-between text-sm">
          <span className="text-zinc-400">
            {currentModule ? (
              <>
                Module en cours : <span className="font-mono text-zinc-200">{currentModule}</span>
              </>
            ) : done ? (
              "Scan terminé"
            ) : (
              "Initialisation…"
            )}
          </span>
          <span className="text-2xl font-semibold tabular-nums text-zinc-100">{findingsCount}</span>
        </div>
        <div className="mt-1 flex items-center justify-between">
          <div className="flex-1">
            <ProgressBar done={modulesDone} total={modulesTotal} />
          </div>
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          {SEVERITY_ORDER.filter((s) => counts[s]).map((s) => (
            <span key={s} className="text-xs" style={{ color: SEVERITY_META[s].hex }}>
              {SEVERITY_META[s].label}: {counts[s]}
            </span>
          ))}
        </div>
      </div>

      {live.error && (
        <p className="mt-4 rounded-md border border-red-900 bg-red-950/40 p-3 text-sm text-red-300">
          Erreur : {live.error}
        </p>
      )}

      {/* Live feed */}
      <h2 className="mt-8 text-sm font-semibold uppercase tracking-wide text-zinc-500">
        Findings en direct
      </h2>
      <div className="mt-3 space-y-2">
        {findings.length === 0 && (
          <p className="rounded-lg border border-dashed border-zinc-800 p-6 text-center text-sm text-zinc-600">
            {done ? "Aucun finding détecté." : "En attente des premiers résultats…"}
          </p>
        )}
        {findings.map((f, i) => (
          <FindingCard key={`${f.module}-${f.timestamp}-${i}`} finding={f} compact />
        ))}
      </div>
    </div>
  );
}
