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
    return <p className="text-sm text-[#8b84a3]">No findings to visualize.</p>;
  }

  return (
    <ResponsiveContainer width="100%" height={Math.max(120, data.length * 44)}>
      <BarChart data={data} layout="vertical" margin={{ left: 8, right: 16, top: 4, bottom: 4 }}>
        <XAxis type="number" allowDecimals={false} stroke="#9691ac" fontSize={12} />
        <YAxis type="category" dataKey="label" width={72} stroke="#635d80" fontSize={12} />
        <Tooltip
          cursor={{ fill: "rgba(76,47,191,0.06)" }}
          formatter={(value: number) => [`${value} finding${value === 1 ? "" : "s"}`, ""]}
          contentStyle={{
            background: "#ffffff",
            border: "1px solid #e6e1f5",
            borderRadius: 10,
            boxShadow: "0 12px 30px -12px rgba(76,47,191,0.35)",
            padding: "8px 12px",
          }}
          labelStyle={{ color: "#241a52", fontWeight: 700, marginBottom: 2 }}
          itemStyle={{ color: "#4c2fbf", fontWeight: 600 }}
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
