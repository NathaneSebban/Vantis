export function ProgressBar({ done, total }: { done: number; total: number }) {
  const pct = total > 0 ? Math.min(100, Math.round((done / total) * 100)) : 0;
  return (
    <div>
      <div className="relative h-2 w-full overflow-hidden rounded-full bg-violetx-soft ring-1 ring-[#e6e1f5]">
        <div
          className="relative h-full rounded-full transition-all duration-700"
          style={{
            width: `${pct}%`,
            background: "linear-gradient(90deg, #3a2a8c, #4c2fbf 55%, #6d4fe0)",
            boxShadow: "0 0 14px -2px rgba(76,47,191,0.7)",
          }}
        >
          <div
            className="absolute inset-0 animate-shimmer opacity-50"
            style={{
              background: "linear-gradient(90deg, transparent, rgba(255,255,255,0.7), transparent)",
              backgroundSize: "200% 100%",
            }}
          />
        </div>
      </div>
      <div className="mt-1.5 text-right text-xs text-[#9691ac]">
        {total > 0 ? `${done}/${total} modules` : "…"}
      </div>
    </div>
  );
}
