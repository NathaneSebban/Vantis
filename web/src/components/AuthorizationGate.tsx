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
    <div className="rounded-lg border border-amber-700/50 bg-amber-950/30 p-4">
      <h2 className="flex items-center gap-2 text-sm font-semibold text-amber-300">
        <span aria-hidden>⚠</span> Autorisation requise
      </h2>
      <p className="mt-2 text-sm leading-relaxed text-amber-100/80">
        Vantis s'apprête à sonder activement{" "}
        <span className="font-mono text-amber-200">{target || "cette cible"}</span>. Cela n'est
        licite que si vous disposez d'une <strong>autorisation explicite</strong> : périmètre d'un
        programme de bug bounty, contrat de test d'intrusion signé, ou propriété de l'actif.
        Scanner un système que vous ne possédez pas ou n'êtes pas autorisé à tester est illégal
        dans la plupart des juridictions.
      </p>

      <label className="mt-4 flex items-start gap-3 text-sm text-amber-50">
        <input
          type="checkbox"
          checked={confirmed}
          onChange={(e) => setConfirmed(e.target.checked)}
          className="mt-0.5 h-4 w-4 shrink-0 cursor-pointer accent-amber-500"
          aria-describedby="auth-help"
        />
        <span>Je confirme être autorisé à tester cette cible.</span>
      </label>

      <button
        type="button"
        onClick={() => canLaunch && onConfirm()}
        disabled={!canLaunch}
        aria-disabled={!canLaunch}
        className="mt-4 w-full rounded-md bg-emerald-600 px-4 py-2.5 text-sm font-semibold text-white transition enabled:hover:bg-emerald-500 disabled:cursor-not-allowed disabled:bg-zinc-700 disabled:text-zinc-400"
      >
        {submitting ? "Lancement…" : "Lancer le scan"}
      </button>
      <p id="auth-help" className="mt-2 text-xs text-amber-200/50">
        Le bouton reste désactivé tant que la case n'est pas cochée.
      </p>
    </div>
  );
}
