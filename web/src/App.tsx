import { NavLink, Route, Routes } from "react-router-dom";
import logoMark from "./assets/logo.png";
import { NewScan } from "./pages/NewScan";
import { ScanLive } from "./pages/ScanLive";
import { ScanReport } from "./pages/ScanReport";
import { ScanHistory } from "./pages/ScanHistory";

function Nav() {
  const linkClass = ({ isActive }: { isActive: boolean }) =>
    `relative rounded-lg px-3.5 py-1.5 text-sm font-medium transition ${
      isActive
        ? "text-violetx-ink bg-violetx-soft shadow-[0_0_0_1px_rgba(76,47,191,0.18)]"
        : "text-[#635d80] hover:text-violetx-ink hover:bg-violetx-tint"
    }`;
  return (
    <header className="sticky top-0 z-30 border-b border-[#ece8f8] bg-white/80 backdrop-blur-xl">
      <div className="mx-auto flex max-w-5xl items-center justify-between px-6 py-3">
        <NavLink to="/" className="group flex items-center gap-2.5">
          <img
            src={logoMark}
            alt="Vantis"
            className="h-9 w-9 rounded-lg object-contain drop-shadow-[0_4px_14px_rgba(76,47,191,0.35)]"
          />
          <span className="flex items-baseline gap-2">
            <span className="text-lg font-extrabold tracking-tight neon-text">Vantis</span>
            <span className="hidden text-[10px] font-semibold uppercase tracking-[0.22em] text-[#9691ac] sm:inline">
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
          <Route path="*" element={<p className="text-[#635d80]">Page not found.</p>} />
        </Routes>
      </main>
    </div>
  );
}
