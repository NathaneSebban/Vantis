import { NavLink, Route, Routes } from "react-router-dom";
import { NewScan } from "./pages/NewScan";
import { ScanLive } from "./pages/ScanLive";
import { ScanReport } from "./pages/ScanReport";
import { ScanHistory } from "./pages/ScanHistory";

function Nav() {
  const linkClass = ({ isActive }: { isActive: boolean }) =>
    `rounded-md px-3 py-1.5 text-sm font-medium transition ${
      isActive ? "bg-zinc-800 text-zinc-100" : "text-zinc-400 hover:text-zinc-200"
    }`;
  return (
    <header className="sticky top-0 z-30 border-b border-zinc-800 bg-zinc-950/80 backdrop-blur">
      <div className="mx-auto flex max-w-5xl items-center justify-between px-6 py-3">
        <NavLink to="/" className="flex items-center gap-2">
          <span className="text-lg font-bold tracking-tight text-emerald-400">Vantis</span>
          <span className="text-xs text-zinc-600">vulnerability scanner</span>
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
      <main className="mx-auto max-w-5xl px-6 py-8">
        <Routes>
          <Route path="/" element={<ScanHistory />} />
          <Route path="/new" element={<NewScan />} />
          <Route path="/scans/:id" element={<ScanLive />} />
          <Route path="/scans/:id/report" element={<ScanReport />} />
          <Route path="*" element={<p className="text-zinc-400">Page not found.</p>} />
        </Routes>
      </main>
    </div>
  );
}
