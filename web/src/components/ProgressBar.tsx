export function ProgressBar({ done, total }: { done: number; total: number }) {
  const pct = total > 0 ? Math.min(100, Math.round((done / total) * 100)) : 0;
  return (
    <div>
      <div className="relative h-2 w-full overflow-hidden rounded-full bg-white/5 ring-1 ring-white/5">
        <div
          className="relative h-full rounded-full transition-all duration-700"
          style={{
            width: `${pct}%`,
            background: "linear-gradient(90deg, #6366f1, #a855f7 55%, #d946ef)",
            boxShadow: "0 0 16px -2px rgba(168,85,247,0.9)",
          }}
        >
          <div
            className="absolute inset-0 animate-shimmer opacity-60"
            style={{
              background: "linear-gradient(90deg, transparent, rgba(255,255,255,0.5), transparent)",
              backgroundSize: "200% 100%",
            }}
          />
        </div>
      </div>
      <div className="mt-1.5 text-right text-xs text-[#6b6482]">
        {total > 0 ? `${done}/${total} modules` : "…"}
      </div>
    </div>
  );
}
