import { useMemo, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import wordmark from "../assets/wordmark.png";
import { ModulePicker } from "../components/ModulePicker";
import { DisclaimerModal } from "../components/DisclaimerModal";
import { useCreateScan, useModules } from "../hooks/useScans";
import { ApiError } from "../api/client";

const FEATURES = [
  { icon: "◎", title: "Injection-point crawler", body: "Links, GET forms, robots/sitemap, bounded BFS and Wayback feed real endpoints to every web module." },
  { icon: "⛨", title: "Authenticated scanning", body: "Attach session headers or cookies and probe the logged-in surface, where the real bugs live." },
  { icon: "⚡", title: "Live results", body: "Findings stream over WebSockets as modules run, with concurrent web/CVE execution for speed." },
  { icon: "⬡", title: "18 detection modules", body: "Recon, TLS, web injection (XSS/SQLi/SSTI/LFI), CORS, secrets-in-JS, content discovery and CVE templates." },
  { icon: "⤓", title: "Reports everywhere", body: "Export to JSON, HTML, Markdown, PDF and SARIF, and drop findings straight into GitHub code scanning." },
  { icon: "◷", title: "Schedule & alert", body: "Run recurring scans, diff against the last run, and get a webhook when new criticals appear." },
];

export function Landing() {
  const navigate = useNavigate();
  const createScan = useCreateScan();
  const { data: modules = [] } = useModules();
  const prefill = (useLocation().state ?? {}) as { target?: string; scope?: string[] };

  const [target, setTarget] = useState(prefill.target ?? "");
  const [scopeInput, setScopeInput] = useState("");
  const [scope, setScope] = useState<string[]>(prefill.scope ?? []);
  const [showOptions, setShowOptions] = useState(false);
  const [showModal, setShowModal] = useState(false);
  // null = "all modules" (default); a Set = an explicit user selection.
  const [selected, setSelected] = useState<Set<string> | null>(null);

  // Automated form-based login (optional): submit the target's own login
  // form ourselves instead of requiring an already-authenticated session.
  const [loginEnabled, setLoginEnabled] = useState(false);
  const [loginUrl, setLoginUrl] = useState("");
  const [loginUsername, setLoginUsername] = useState("");
  const [loginPassword, setLoginPassword] = useState("");

  const allNames = useMemo(() => new Set(modules.map((m) => m.name)), [modules]);
  const effective = selected ?? allNames;
  const targetValid = target.trim().length > 0;
  const canLaunch = targetValid && effective.size > 0;

  function addScope() {
    const v = scopeInput.trim();
    if (v && !scope.includes(v)) setScope([...scope, v]);
    setScopeInput("");
  }

  async function launch() {
    try {
      const res = await createScan.mutateAsync({
        target: target.trim(),
        scope,
        modules: ["recon", "web", "cve"],
        module_names: selected ? Array.from(selected) : undefined,
        login_url: loginEnabled ? loginUrl.trim() || undefined : undefined,
        login_username: loginEnabled ? loginUsername.trim() || undefined : undefined,
        login_password: loginEnabled ? loginPassword || undefined : undefined,
        authorized: true, // guaranteed by the disclaimer modal — the only caller
      });
      navigate(`/scans/${res.scan_id}`);
    } catch {
      /* surfaced below */
    }
  }

  return (
    <div className="mx-auto max-w-4xl">
      {/* ---- Hero ---- */}
      <section className="relative flex flex-col items-center pt-10 text-center">
        <div className="relative animate-reveal">
          {/* soft violet halo drifting behind the wordmark */}
          <span className="pointer-events-none absolute inset-0 -z-10 grid place-items-center">
            <span className="h-40 w-72 rounded-full bg-violetx/20 blur-3xl animate-pulseglow" />
          </span>
          <img
            src={wordmark}
            alt="Vantis"
            className="h-16 animate-float object-contain drop-shadow-[0_14px_36px_rgba(76,47,191,0.4)] sm:h-20"
          />
        </div>

        <h1 className="mt-6 max-w-2xl animate-reveal text-balance text-4xl font-extrabold leading-[1.1] tracking-tight text-violetx-ink [animation-delay:0.15s] sm:text-5xl">
          Find what attackers find,{" "}
          <span
            className="bg-clip-text text-transparent [background-size:200%_auto] animate-gradient"
            style={{ backgroundImage: "linear-gradient(90deg,#3a2a8c,#6d4fe0,#4c2fbf,#6d4fe0)" }}
          >
            before they do.
          </span>
        </h1>
        <p className="mt-4 max-w-xl animate-reveal text-[15px] leading-relaxed text-[#5b5676] [animation-delay:0.2s]">
          Vantis is a modular vulnerability scanner for <strong>authorized</strong> security testing, combining recon,
          web-app testing and CVE detection in one sweep, with live results and a plugin for every check.
        </p>

        <div className="mt-5 flex animate-reveal flex-wrap justify-center gap-2 text-xs font-medium text-violetx [animation-delay:0.25s]">
          {[`${modules.length || 18} modules`, "real-time streaming", "5 export formats", "detection-only"].map((t) => (
            <span key={t} className="rounded-full border border-violetx/20 bg-violetx-soft px-3 py-1">{t}</span>
          ))}
        </div>
      </section>

      {/* ---- Launcher ---- */}
      <section className="mt-10 animate-reveal [animation-delay:0.3s]">
        <div className="card relative overflow-hidden p-2">
          {/* animated scan sweep line */}
          <span className="pointer-events-none absolute inset-y-0 left-0 w-1/3 animate-sweep bg-gradient-to-r from-transparent via-violetx/10 to-transparent" />
          <div className="relative flex flex-col gap-2 sm:flex-row">
            <div className="flex flex-1 items-center gap-2 rounded-xl border border-[#eae5f8] bg-white px-3">
              <span className="text-violetx/60">⌖</span>
              <input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && canLaunch && setShowModal(true)}
                placeholder="https://example.com (an authorized target)"
                className="w-full bg-transparent py-3.5 text-sm text-violetx-ink outline-none placeholder:text-[#a9a3bd]"
              />
            </div>
            <button
              type="button"
              onClick={() => setShowOptions((s) => !s)}
              className={`btn-ghost ${showOptions ? "border-violetx/45 bg-violetx-soft" : ""}`}
            >
              ⚙ Options {selected ? `· ${selected.size}` : ""}
              <span className={`transition ${showOptions ? "rotate-180" : ""}`}>▾</span>
            </button>
            <button type="button" disabled={!canLaunch} onClick={() => setShowModal(true)} className="btn-primary">
              ▶ Launch scan
            </button>
          </div>

          {/* Options dropdown (filter menu) */}
          {showOptions && (
            <div className="relative mt-2 animate-reveal rounded-xl border border-[#eae5f8] bg-violetx-tint/60 p-4">
              <div className="mb-4">
                <label className="text-xs font-semibold uppercase tracking-wide text-[#8b84a3]">Additional scope</label>
                <div className="mt-1.5 flex gap-2">
                  <input
                    value={scopeInput}
                    onChange={(e) => setScopeInput(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && (e.preventDefault(), addScope())}
                    placeholder="api.example.com, 10.0.0.0/24…"
                    className="field flex-1"
                  />
                  <button type="button" onClick={addScope} className="btn-ghost">Add</button>
                </div>
                {scope.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-2">
                    {scope.map((s) => (
                      <span key={s} className="inline-flex items-center gap-1.5 rounded-full bg-white px-2.5 py-1 text-xs font-mono text-violetx-deep ring-1 ring-[#e6e1f5]">
                        {s}
                        <button onClick={() => setScope(scope.filter((x) => x !== s))} className="text-[#9691ac] hover:text-violetx-ink">✕</button>
                      </span>
                    ))}
                  </div>
                )}
              </div>

              <div className="mb-2 flex items-center justify-between">
                <label className="text-xs font-semibold uppercase tracking-wide text-[#8b84a3]">Modules</label>
                <div className="flex gap-2 text-xs">
                  <button onClick={() => setSelected(null)} className="font-medium text-violetx hover:underline">Select all</button>
                  <span className="text-[#cfc7e6]">·</span>
                  <button onClick={() => setSelected(new Set())} className="font-medium text-violetx hover:underline">Clear</button>
                </div>
              </div>
              <ModulePicker selected={effective} onChange={(next) => setSelected(next)} />

              <div className="mt-4 border-t border-[#eae5f8] pt-4">
                <label className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-[#8b84a3]">
                  <input
                    type="checkbox"
                    checked={loginEnabled}
                    onChange={(e) => setLoginEnabled(e.target.checked)}
                    className="h-4 w-4 rounded border-[#cfc7e6] text-violetx accent-violetx"
                  />
                  Automated login
                </label>
                <p className="mt-1 text-xs text-[#9691ac]">
                  Vantis submits the target's own login form itself with these credentials, and scans the
                  authenticated area with the resulting session. Use a dedicated test account, never your real one.
                </p>
                {loginEnabled && (
                  <div className="mt-3 grid gap-2 sm:grid-cols-3">
                    <input
                      value={loginUrl}
                      onChange={(e) => setLoginUrl(e.target.value)}
                      placeholder="Login page URL"
                      className="field"
                    />
                    <input
                      value={loginUsername}
                      onChange={(e) => setLoginUsername(e.target.value)}
                      placeholder="Username / email"
                      className="field"
                    />
                    <input
                      value={loginPassword}
                      onChange={(e) => setLoginPassword(e.target.value)}
                      placeholder="Password"
                      type="password"
                      className="field"
                    />
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
        {createScan.isError && (
          <p className="mt-3 text-sm text-red-600">
            Failed to launch: {createScan.error instanceof ApiError ? createScan.error.message : "unknown error"}
          </p>
        )}
        <p className="mt-3 text-center text-xs text-[#9691ac]">
          You will confirm you are authorized to test the target before the scan starts.
        </p>
      </section>

      {/* ---- Features / promo ---- */}
      <section className="mt-16">
        <h2 className="text-center text-xs font-semibold uppercase tracking-[0.2em] text-[#9691ac]">Why Vantis</h2>
        <div className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {FEATURES.map((f, i) => (
            <div
              key={f.title}
              className="card card-hover animate-reveal p-4"
              style={{ animationDelay: `${0.35 + i * 0.05}s` }}
            >
              <div className="grid h-9 w-9 place-items-center rounded-lg bg-violetx-soft text-lg text-violetx">{f.icon}</div>
              <h3 className="mt-3 font-bold text-violetx-ink">{f.title}</h3>
              <p className="mt-1 text-sm leading-relaxed text-[#635d80]">{f.body}</p>
            </div>
          ))}
        </div>
      </section>

      {showModal && (
        <DisclaimerModal
          target={target.trim()}
          submitting={createScan.isPending}
          onConfirm={launch}
          onClose={() => setShowModal(false)}
        />
      )}
    </div>
  );
}
