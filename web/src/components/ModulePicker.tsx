import { useMemo } from "react";
import { useModules } from "../hooks/useScans";
import type { ModuleCategory } from "../api/types";

const CATEGORY_META: Record<ModuleCategory, { label: string; blurb: string }> = {
  recon: { label: "Recon", blurb: "Map the attack surface" },
  web: { label: "Web", blurb: "Probe the application" },
  cve: { label: "CVE", blurb: "Match known issues" },
};
const ORDER: ModuleCategory[] = ["recon", "web", "cve"];

interface Props {
  selected: Set<string>;
  onChange: (next: Set<string>) => void;
}

// A visible, filter-style checkbox — the checked state is a solid violet box
// with a white tick (no more transparent/invisible checked state).
function Check({ on }: { on: boolean }) {
  return (
    <span
      className={`grid h-4 w-4 shrink-0 place-items-center rounded-[5px] border transition ${
        on ? "border-violetx bg-violetx text-white shadow-[0_0_10px_-2px_rgba(76,47,191,0.8)]" : "border-[#cbc3e3] bg-white"
      }`}
    >
      {on && (
        <svg viewBox="0 0 12 12" className="h-3 w-3" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round">
          <path d="M2.5 6.5l2.2 2.2L9.5 3.5" />
        </svg>
      )}
    </span>
  );
}

export function ModulePicker({ selected, onChange }: Props) {
  const { data: modules = [], isLoading } = useModules();

  const grouped = useMemo(() => {
    const g: Record<string, { name: string; description: string }[]> = { recon: [], web: [], cve: [] };
    for (const m of modules) (g[m.category] ??= []).push({ name: m.name, description: m.description });
    return g;
  }, [modules]);

  function toggle(name: string) {
    const next = new Set(selected);
    next.has(name) ? next.delete(name) : next.add(name);
    onChange(next);
  }
  function toggleCategory(cat: ModuleCategory) {
    const names = grouped[cat].map((m) => m.name);
    const allOn = names.every((n) => selected.has(n));
    const next = new Set(selected);
    names.forEach((n) => (allOn ? next.delete(n) : next.add(n)));
    onChange(next);
  }

  if (isLoading) return <p className="text-sm text-[#8b84a3]">Loading modules…</p>;

  return (
    <div className="space-y-4">
      {ORDER.map((cat) => {
        const items = grouped[cat] ?? [];
        if (!items.length) return null;
        const onCount = items.filter((m) => selected.has(m.name)).length;
        const allOn = onCount === items.length;
        return (
          <div key={cat} className="rounded-xl border border-[#eae5f8] bg-white/70 p-3">
            <button
              type="button"
              onClick={() => toggleCategory(cat)}
              className="flex w-full items-center justify-between rounded-lg px-1 py-0.5 text-left"
            >
              <span className="flex items-center gap-2.5">
                <Check on={allOn} />
                <span>
                  <span className="text-sm font-bold text-violetx-ink">{CATEGORY_META[cat].label}</span>
                  <span className="ml-2 text-xs text-[#9691ac]">{CATEGORY_META[cat].blurb}</span>
                </span>
              </span>
              <span className="rounded-full bg-violetx-soft px-2 py-0.5 text-[11px] font-semibold text-violetx">
                {onCount}/{items.length}
              </span>
            </button>

            <div className="mt-2 grid gap-1.5 sm:grid-cols-2">
              {items.map((m) => {
                const on = selected.has(m.name);
                return (
                  <button
                    type="button"
                    key={m.name}
                    onClick={() => toggle(m.name)}
                    title={m.description}
                    className={`flex items-center gap-2.5 rounded-lg border px-2.5 py-2 text-left transition ${
                      on ? "border-violetx/40 bg-violetx-soft" : "border-transparent bg-[#f7f5fd] hover:border-[#e6e1f5]"
                    }`}
                  >
                    <Check on={on} />
                    <span className="min-w-0">
                      <span className="block truncate font-mono text-xs font-medium text-violetx-ink">{m.name}</span>
                      <span className="block truncate text-[11px] text-[#9691ac]">{m.description}</span>
                    </span>
                  </button>
                );
              })}
            </div>
          </div>
        );
      })}
    </div>
  );
}
