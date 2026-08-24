import { useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { AuthorizationGate } from "../components/AuthorizationGate";
import { useCreateScan } from "../hooks/useScans";
import { MODULE_CATEGORIES, type ModuleCategory } from "../api/types";
import { ApiError } from "../api/client";

const MODULE_LABELS: Record<ModuleCategory, { title: string; detail: string }> = {
  recon: { title: "Recon", detail: "subdomains, ports, technologies" },
  web: { title: "Web", detail: "headers, reflected XSS, SQLi, exposed paths" },
  cve: { title: "CVE", detail: "Nuclei-style YAML templates" },
};

interface PrefillState {
  target?: string;
  scope?: string[];
  modules?: string[];
}

export function NewScan() {
  const navigate = useNavigate();
  const createScan = useCreateScan();

  // Prefill from a "Relaunch" action in the history (still re-confirmed below).
  const prefill = (useLocation().state ?? {}) as PrefillState;

  const [target, setTarget] = useState(prefill.target ?? "");
  const [scopeInput, setScopeInput] = useState("");
  const [scope, setScope] = useState<string[]>(prefill.scope ?? []);
  const [modules, setModules] = useState<ModuleCategory[]>(
    (prefill.modules?.filter((m): m is ModuleCategory =>
      (MODULE_CATEGORIES as readonly string[]).includes(m),
    ) as ModuleCategory[]) ?? [...MODULE_CATEGORIES],
  );

  const targetValid = target.trim().length > 0;

  function addScope() {
    const v = scopeInput.trim();
    if (v && !scope.includes(v)) setScope([...scope, v]);
    setScopeInput("");
  }

  function toggleModule(m: ModuleCategory) {
    setModules((prev) => (prev.includes(m) ? prev.filter((x) => x !== m) : [...prev, m]));
  }

  async function launch() {
    try {
      const res = await createScan.mutateAsync({
        target: target.trim(),
        scope,
        modules,
        authorized: true, // guaranteed by AuthorizationGate — the only caller
      });
      navigate(`/scans/${res.scan_id}`);
    } catch {
      /* error surfaced below via createScan.error */
    }
  }

  return (
    <div className="mx-auto max-w-2xl">
      <h1 className="text-2xl font-bold text-white">New scan</h1>
      <p className="mt-1 text-sm text-zinc-500">
        Configure the target and modules, then confirm authorization to launch.
      </p>

      <div className="mt-8 space-y-6">
        {/* Target */}
        <div>
          <label className="block text-sm font-medium text-zinc-300">Target</label>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="https://example.com"
            className="field mt-1.5"
          />
        </div>

        {/* Scope */}
        <div>
          <label className="block text-sm font-medium text-zinc-300">
            Additional scope <span className="text-zinc-500">(optional)</span>
          </label>
          <div className="mt-1.5 flex gap-2">
            <input
              type="text"
              value={scopeInput}
              onChange={(e) => setScopeInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && (e.preventDefault(), addScope())}
              placeholder="api.example.com, 10.0.0.0/24…"
              className="field flex-1"
            />
            <button
              type="button"
              onClick={addScope}
              className="btn-ghost"
            >
              Add
            </button>
          </div>
          {scope.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-2">
              {scope.map((s) => (
                <span
                  key={s}
                  className="inline-flex items-center gap-1.5 rounded-full bg-zinc-800 px-2.5 py-1 text-xs font-mono text-zinc-300"
                >
                  {s}
                  <button onClick={() => setScope(scope.filter((x) => x !== s))} className="text-zinc-500 hover:text-zinc-200">
                    ✕
                  </button>
                </span>
              ))}
            </div>
          )}
          <p className="mt-1.5 text-xs text-zinc-600">
            By default the scope is limited to the target's domain and its subdomains.
          </p>
        </div>

        {/* Modules */}
        <div>
          <label className="block text-sm font-medium text-zinc-300">Modules</label>
          <div className="mt-2 grid gap-2 sm:grid-cols-3">
            {MODULE_CATEGORIES.map((m) => {
              const on = modules.includes(m);
              return (
                <button
                  type="button"
                  key={m}
                  onClick={() => toggleModule(m)}
                  className={`rounded-lg border p-3 text-left transition ${
                    on ? "border-violet-600 bg-violet-950/30" : "border-zinc-800 bg-zinc-900 hover:border-zinc-700"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-zinc-100">{MODULE_LABELS[m].title}</span>
                    <span className={`h-4 w-4 rounded border ${on ? "border-violet-500 bg-violet-500" : "border-zinc-600"}`}>
                      {on && <span className="block text-center text-xs leading-4 text-white">✓</span>}
                    </span>
                  </div>
                  <p className="mt-1 text-xs text-zinc-500">{MODULE_LABELS[m].detail}</p>
                </button>
              );
            })}
          </div>
          {modules.length === 0 && <p className="mt-1.5 text-xs text-red-400">Select at least one module.</p>}
        </div>

        {/* Authorization gate — mandatory confirmation before launch */}
        {targetValid && modules.length > 0 ? (
          <AuthorizationGate target={target.trim()} submitting={createScan.isPending} onConfirm={launch} />
        ) : (
          <p className="card p-4 text-sm text-zinc-500">
            Enter a target and at least one module to show the authorization confirmation.
          </p>
        )}

        {createScan.isError && (
          <p className="text-sm text-red-400">
            Failed to launch:{" "}
            {createScan.error instanceof ApiError ? createScan.error.message : "unknown error"}
          </p>
        )}
      </div>
    </div>
  );
}
