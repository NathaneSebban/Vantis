import { NavLink, Route, Routes } from "react-router-dom";
import { NewScan } from "./pages/NewScan";
import { ScanLive } from "./pages/ScanLive";
import { ScanReport } from "./pages/ScanReport";
import { ScanHistory } from "./pages/ScanHistory";

function Nav() {
  const linkClass = ({ isActive }: { isActive: boolean }) =>
    `relative rounded-lg px-3.5 py-1.5 text-sm font-medium transition ${
      isActive
        ? "text-white shadow-[0_0_0_1px_rgba(168,85,247,0.4),0_0_18px_-6px_rgba(168,85,247,0.7)] bg-violet-500/10"
        : "text-[#9a91b4] hover:text-white hover:bg-white/5"
    }`;
  return (
    <header className="sticky top-0 z-30 border-b border-white/5 bg-ink-950/60 backdrop-blur-xl">
      <div className="mx-auto flex max-w-5xl items-center justify-between px-6 py-3.5">
        <NavLink to="/" className="group flex items-center gap-2.5">
          <span className="relative grid h-8 w-8 place-items-center rounded-lg bg-gradient-to-br from-violet-500 to-fuchsia-600 shadow-[0_0_18px_-2px_rgba(168,85,247,0.8)]">
            <span className="absolute inset-0 rounded-lg ring-1 ring-white/20" />
            <svg viewBox="0 0 24 24" className="h-4.5 w-4.5" fill="none" stroke="white" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" style={{ width: 18, height: 18 }}>
              <path d="M12 2l8 3v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5l8-3z" />
            </svg>
          </span>
          <span className="flex items-baseline gap-2">
            <span className="text-lg font-extrabold tracking-tight text-white neon-text">Vantis</span>
            <span className="hidden text-[10px] font-medium uppercase tracking-[0.2em] text-[#6b6482] sm:inline">
              scanner
            </span>
          </span>
        </NavLink>
        <nav className="flex items-center gap-1">
          <NavLink to="/" end className={linkClass}>
            History
          </NavLink>
          <NavLink to="/new" className={linkClass}>
            New scan
          </NavLink>
        </nav>
      </div>
    </header>
  );
}

export default function App() {
  return (
    <div className="min-h-full">
      <Nav />
      <main className="mx-auto max-w-5xl px-6 py-10">
        <Routes>
          <Route path="/" element={<ScanHistory />} />
          <Route path="/new" element={<NewScan />} />
          <Route path="/scans/:id" element={<ScanLive />} />
          <Route path="/scans/:id/report" element={<ScanReport />} />
          <Route path="*" element={<p className="text-[#9a91b4]">Page not found.</p>} />
        </Routes>
      </main>
    </div>
  );
}
