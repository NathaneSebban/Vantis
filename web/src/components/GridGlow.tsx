import { useEffect, useRef } from "react";

// A neon-violet spotlight over the background grid that follows the cursor:
// a brighter grid layer, masked to a soft circle around the pointer. The
// pointer position is written to CSS variables (rAF-throttled) so the paint
// stays on the compositor and the effect feels instant without jank.
export function GridGlow() {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    let raf = 0;
    let x = -400;
    let y = -400;

    const apply = () => {
      raf = 0;
      const el = ref.current;
      if (el) {
        el.style.setProperty("--mx", `${x}px`);
        el.style.setProperty("--my", `${y}px`);
        el.style.opacity = "1";
      }
    };
    const onMove = (e: MouseEvent) => {
      x = e.clientX;
      y = e.clientY;
      if (!raf) raf = requestAnimationFrame(apply);
    };
    const onLeave = () => {
      const el = ref.current;
      if (el) el.style.opacity = "0";
    };

    window.addEventListener("mousemove", onMove, { passive: true });
    document.addEventListener("mouseleave", onLeave);
    return () => {
      window.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseleave", onLeave);
      if (raf) cancelAnimationFrame(raf);
    };
  }, []);

  return <div ref={ref} className="grid-glow" aria-hidden />;
}
