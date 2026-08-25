// Thin neon dashes that run along grid rows/columns and cross the page
// intermittently (pure CSS animations, see .beam in index.css). Each beam is
// pinned to a grid coordinate (multiple of 46px) with its own duration/delay
// so the crossings feel scattered rather than synchronized.
const H_ROWS = [
  { top: 138, dur: 8, delay: 0 },
  { top: 368, dur: 11, delay: 4.5 },
  { top: 598, dur: 9.5, delay: 2 },
  { top: 828, dur: 12.5, delay: 7 },
];
const V_COLS = [
  { left: 230, dur: 10, delay: 1.5 },
  { left: 506, dur: 13, delay: 6 },
  { left: 782, dur: 9, delay: 3.5 },
  { left: 1058, dur: 12, delay: 9 },
];

export function GridFlow() {
  return (
    <>
      {H_ROWS.map((b, i) => (
        <span
          key={`h${i}`}
          className="beam beam-h"
          aria-hidden
          style={{ top: b.top, animationDuration: `${b.dur}s`, animationDelay: `${b.delay}s` }}
        />
      ))}
      {V_COLS.map((b, i) => (
        <span
          key={`v${i}`}
          className="beam beam-v"
          aria-hidden
          style={{ left: b.left, animationDuration: `${b.dur}s`, animationDelay: `${b.delay}s` }}
        />
      ))}
    </>
  );
}
