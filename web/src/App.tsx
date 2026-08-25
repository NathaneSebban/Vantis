import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import wordmark from "./assets/wordmark.png";
import { Footer } from "./components/Footer";
import { GridFlow } from "./components/GridFlow";
import { Landing } from "./pages/Landing";
import { ScanLive } from "./pages/ScanLive";
import { ScanReport } from "./pages/ScanReport";
import { ScanHistory } from "./pages/ScanHistory";
import { Trend } from "./pages/Trend";

function Nav() {
  const linkClass = ({ isActive }: { isActive: boolean }) =>
    `relative px-1 py-1.5 text-sm font-medium transition after:absolute after:inset-x-0 after:-bottom-[1px] after:h-[2px] after:origin-center after:rounded-full after:bg-violetx after:transition-transform ${
      isActive
        ? "text-violetx-ink after:scale-x-100"
        : "text-[#635d80] hover:text-violetx-ink after:scale-x-0 hover:after:scale-x-100"
    }`;
  return (
    <header className="sticky top-0 z-30 border-b border-[#ece8f8] bg-white/80 backdrop-blur-xl">
      <div className="mx-auto flex max-w-5xl items-center justify-between px-6 py-2.5">
        <NavLink to="/" className="flex items-center">
          <img src={wordmark} alt="Vantis" className="h-6 object-contain" />
        </NavLink>
        <nav className="flex items-center gap-6">
          <NavLink to="/" end className={linkClass}>
            Scan
          </NavLink>
          <NavLink to="/history" className={linkClass}>
            History
          </NavLink>
          <NavLink to="/trend" className={linkClass}>
            Trend
          </NavLink>
        </nav>
      </div>
    </header>
  );
}

export default function App() {
  return (
    <div className="flex min-h-full flex-col">
      <GridFlow />
      <Nav />
      <main className="mx-auto w-full max-w-5xl flex-1 px-6 py-8">
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/history" element={<ScanHistory />} />
          <Route path="/trend" element={<Trend />} />
          <Route path="/new" element={<Navigate to="/" replace />} />
          <Route path="/scans/:id" element={<ScanLive />} />
          <Route path="/scans/:id/report" element={<ScanReport />} />
          <Route path="*" element={<p className="text-[#635d80]">Page not found.</p>} />
        </Routes>
      </main>
      <Footer />
    </div>
  );
}
