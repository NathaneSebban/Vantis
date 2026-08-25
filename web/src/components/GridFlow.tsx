// Automatic neon: two bright-grid layers revealed through soft blobs whose
// positions are animated across the viewport (pure CSS, see index.css). No
// pointer interaction — the light drifts along the grid lines on its own.
export function GridFlow() {
  return (
    <>
      <div className="grid-flow grid-flow-a" aria-hidden />
      <div className="grid-flow grid-flow-b" aria-hidden />
    </>
  );
}
