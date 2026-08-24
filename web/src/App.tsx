import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import logoMark from "./assets/logo.png";
import wordmark from "./assets/wordmark.png";
import { Landing } from "./pages/Landing";
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
      <div className="mx-auto flex max-w-5xl items-center justify-between px-6 py-2.5">
        <NavLink to="/" className="flex items-center gap-2.5">
          <img
            src={logoMark}
            alt="Vantis"
            className="h-11 w-11 object-contain drop-shadow-[0_6px_16px_rgba(76,47,191,0.35)] transition group-hover:scale-105"
          />
          <img src={wordmark} alt="Vantis" className="h-5 object-contain" />
        </NavLink>
        <nav className="flex items-center gap-1">
          <NavLink to="/" end className={linkClass}>
            Scan
          </NavLink>
          <NavLink to="/history" className={linkClass}>
            History
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
          <Route path="/" element={<Landing />} />
          <Route path="/history" element={<ScanHistory />} />
          <Route path="/new" element={<Navigate to="/" replace />} />
          <Route path="/scans/:id" element={<ScanLive />} />
          <Route path="/scans/:id/report" element={<ScanReport />} />
          <Route path="*" element={<p className="text-[#635d80]">Page not found.</p>} />
        </Routes>
      </main>
    </div>
  );
}
