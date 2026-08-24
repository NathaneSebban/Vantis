import { useEffect } from "react";
import { AuthorizationGate } from "./AuthorizationGate";

interface Props {
  target: string;
  submitting?: boolean;
  onConfirm: () => void;
  onClose: () => void;
}

// The authorization disclaimer, shown as a modal popup when launching a scan.
// The gate itself remains the single non-bypassable confirmation.
export function DisclaimerModal({ target, submitting, onConfirm, onClose }: Props) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div
      className="fixed inset-0 z-50 grid place-items-center bg-violetx-ink/30 p-4 backdrop-blur-md"
      onClick={onClose}
    >
      <div
        className="w-full max-w-lg animate-reveal rounded-2xl border border-[#e6e1f5] bg-white p-5 shadow-[0_40px_100px_-30px_rgba(76,47,191,0.55)]"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-3 flex items-start justify-between">
          <div>
            <div className="text-[11px] font-semibold uppercase tracking-[0.18em] text-violetx">Final step</div>
            <h2 className="mt-0.5 text-lg font-bold text-violetx-ink">Confirm authorization</h2>
          </div>
          <button
            onClick={onClose}
            aria-label="Close"
            className="rounded-lg p-1.5 text-[#9691ac] transition hover:bg-violetx-soft hover:text-violetx-ink"
          >
            ✕
          </button>
        </div>
        <AuthorizationGate target={target} submitting={submitting} onConfirm={onConfirm} />
      </div>
    </div>
  );
}
