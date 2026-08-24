import { useState } from "react";

interface Props {
  target: string;
  submitting?: boolean;
  onConfirm: () => void;
}

// The web equivalent of Engine.confirm_authorization. This component owns BOTH
// the explicit checkbox and the launch button so a scan can never be started
// without confirmation — there is no code path from here to onConfirm() that
// skips the checkbox. The "Lancer le scan" button stays disabled until the
// user ticks the box. Do not add a bypass, whatever the ask to "simplify".
export function AuthorizationGate({ target, submitting, onConfirm }: Props) {
  const [confirmed, setConfirmed] = useState(false);
  const canLaunch = confirmed && !submitting;

  return (
    <div className="rounded-xl border border-amber-500/25 bg-amber-500/[0.06] p-4 shadow-[inset_0_0_30px_-14px_rgba(245,158,11,0.5)]">
      <h2 className="flex items-center gap-2 text-sm font-semibold text-amber-300">
        <span aria-hidden>⚠</span> Authorization required
      </h2>
      <p className="mt-2 text-sm leading-relaxed text-amber-100/80">
        Vantis is about to actively probe{" "}
        <span className="font-mono text-amber-200">{target || "this target"}</span>. This is only
        lawful if you have <strong>explicit authorization</strong>: a bug bounty program scope, a
        signed penetration-testing agreement, or ownership of the asset. Scanning a system you do
        not own or are not authorized to test is illegal in most jurisdictions.
      </p>

      <label className="mt-4 flex items-start gap-3 text-sm text-amber-50">
        <input
          type="checkbox"
          checked={confirmed}
          onChange={(e) => setConfirmed(e.target.checked)}
          className="mt-0.5 h-4 w-4 shrink-0 cursor-pointer accent-amber-500"
          aria-describedby="auth-help"
        />
        <span>I confirm I am authorized to test this target.</span>
      </label>

      <button
        type="button"
        onClick={() => canLaunch && onConfirm()}
        disabled={!canLaunch}
        aria-disabled={!canLaunch}
        className="btn-primary mt-4 w-full"
      >
        {submitting ? "Launching…" : "▶  Launch scan"}
      </button>
      <p id="auth-help" className="mt-2 text-xs text-amber-200/50">
        The button stays disabled until the box is checked.
      </p>
    </div>
  );
}
