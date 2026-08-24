import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { SeverityCounts } from "../api/types";
import { SEVERITY_ORDER } from "../api/types";
import { SEVERITY_META } from "./severity";

// Horizontal bar chart of finding counts by severity (spec: Recharts, barres
// horizontales). Severities with no findings are dropped so the chart stays
// readable.
export function SeverityChart({ counts }: { counts: SeverityCounts }) {
  const data = SEVERITY_ORDER.map((sev) => ({
    severity: sev,
    label: SEVERITY_META[sev].label,
    value: counts[sev],
    fill: SEVERITY_META[sev].hex,
  })).filter((d) => d.value > 0);

  if (data.length === 0) {
    return <p className="text-sm text-zinc-500">Aucun finding à visualiser.</p>;
  }

  return (
    <ResponsiveContainer width="100%" height={Math.max(120, data.length * 44)}>
      <BarChart data={data} layout="vertical" margin={{ left: 8, right: 16, top: 4, bottom: 4 }}>
        <XAxis type="number" allowDecimals={false} stroke="#71717a" fontSize={12} />
        <YAxis type="category" dataKey="label" width={72} stroke="#a1a1aa" fontSize={12} />
        <Tooltip
          cursor={{ fill: "rgba(255,255,255,0.04)" }}
          contentStyle={{ background: "#18181b", border: "1px solid #3f3f46", borderRadius: 8, color: "#e4e4e7" }}
        />
        <Bar dataKey="value" radius={[0, 4, 4, 0]}>
          {data.map((d) => (
            <Cell key={d.severity} fill={d.fill} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
