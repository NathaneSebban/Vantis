import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useTrend } from "../hooks/useScans";
import { SEVERITY_META } from "../components/severity";

// Findings-over-time for one target, so a repeat-scan workflow shows whether
// things are getting better or worse instead of just the latest snapshot.
export function Trend() {
  const [params, setParams] = useSearchParams();
  const initial = params.get("target") ?? "";
  const [input, setInput] = useState(initial);
  const target = params.get("target") ?? undefined;
  const { data, isLoading } = useTrend(target);

  function submit(e: React.FormEvent) {
    e.preventDefault();
    const v = input.trim();
    if (v) setParams({ target: v });
  }

  const chartData = (data?.points ?? []).map((p) => ({
    date: new Date(p.created_at).toLocaleDateString(),
    total: p.findings_count,
    critical: p.severity_counts.critical,
    high: p.severity_counts.high,
    medium: p.severity_counts.medium,
    low: p.severity_counts.low,
    info: p.severity_counts.info,
  }));

  return (
    <div className="mx-auto max-w-5xl">
      <h1 className="text-2xl font-bold text-violetx-ink">Trend</h1>
      <p className="mt-1 text-sm text-[#635d80]">
        Findings over time for a single target, across every completed scan of it.
      </p>

      <form onSubmit={submit} className="mt-6 flex flex-col gap-2 sm:flex-row">
        <div className="flex flex-1 items-center gap-2 rounded-xl border border-[#eae5f8] bg-white px-3">
          <span className="text-violetx/60">⌖</span>
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="https://example.com"
            className="w-full bg-transparent py-3.5 text-sm text-violetx-ink outline-none placeholder:text-[#a9a3bd]"
          />
        </div>
        <button type="submit" className="btn-primary">
          View trend
        </button>
      </form>

      {!target && (
        <p className="mt-8 text-sm text-[#9691ac]">
          Enter a target above (or open this page from a scan's history row) to see its trend.
        </p>
      )}

      {target && isLoading && <p className="mt-8 text-sm text-[#9691ac]">Loading…</p>}

      {target && !isLoading && data && data.points.length === 0 && (
        <p className="mt-8 text-sm text-[#9691ac]">No completed scans of {target} yet.</p>
      )}

      {target && !isLoading && data && data.points.length > 0 && (
        <div className="card mt-6 p-6">
          <ResponsiveContainer width="100%" height={320}>
            <LineChart data={chartData} margin={{ left: 8, right: 16, top: 8, bottom: 4 }}>
              <XAxis dataKey="date" stroke="#9691ac" fontSize={12} />
              <YAxis allowDecimals={false} stroke="#9691ac" fontSize={12} />
              <Tooltip
                contentStyle={{
                  background: "#ffffff",
                  border: "1px solid #e6e1f5",
                  borderRadius: 10,
                  boxShadow: "0 12px 30px -12px rgba(76,47,191,0.35)",
                }}
              />
              <Line type="monotone" dataKey="total" name="Total" stroke="#241a52" strokeWidth={2} dot={{ r: 3 }} />
              <Line type="monotone" dataKey="critical" name="Critical" stroke={SEVERITY_META.critical.hex} strokeWidth={1.5} dot={false} />
              <Line type="monotone" dataKey="high" name="High" stroke={SEVERITY_META.high.hex} strokeWidth={1.5} dot={false} />
              <Line type="monotone" dataKey="medium" name="Medium" stroke={SEVERITY_META.medium.hex} strokeWidth={1.5} dot={false} />
            </LineChart>
          </ResponsiveContainer>
          <p className="mt-2 text-xs text-[#9691ac]">{data.points.length} completed scan(s) of {target}</p>
        </div>
      )}
    </div>
  );
}
