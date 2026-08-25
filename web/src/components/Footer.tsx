import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import wordmark from "../assets/wordmark.png";

const REPO = "https://github.com/NathaneSebban/Vantis";
const AUTHOR = "https://www.linkedin.com/in/nathane-sebban";

function Col({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div>
      <h3 className="text-[11px] font-semibold uppercase tracking-[0.16em] text-[#9691ac]">{title}</h3>
      <ul className="mt-3 space-y-2 text-sm">{children}</ul>
    </div>
  );
}

const ext = "text-[#4b4668] transition hover:text-violetx";

export function Footer() {
  return (
    <footer className="mt-16 border-t border-[#ece8f8] bg-white/60 backdrop-blur">
      <div className="mx-auto max-w-5xl px-6 py-10">
        <div className="grid gap-8 sm:grid-cols-2 lg:grid-cols-4">
          {/* Brand */}
          <div className="lg:col-span-1">
            <img src={wordmark} alt="Vantis" className="h-5 object-contain" />
            <p className="mt-3 max-w-xs text-sm leading-relaxed text-[#635d80]">
              Modular vulnerability scanner for recon, web and CVE detection.
            </p>
            <span className="mt-3 inline-flex items-center gap-1.5 rounded-full border border-violetx/20 bg-violetx-soft px-2.5 py-1 text-[11px] font-semibold text-violetx">
              ● Free &amp; open-source
            </span>
          </div>

          <Col title="App">
            <li><Link to="/" className={ext}>New scan</Link></li>
            <li><Link to="/history" className={ext}>Scan history</Link></li>
          </Col>

          <Col title="Project">
            <li><a href={REPO} target="_blank" rel="noreferrer" className={ext}>GitHub repository</a></li>
            <li><a href={`${REPO}#readme`} target="_blank" rel="noreferrer" className={ext}>Documentation</a></li>
            <li><a href={`${REPO}/blob/main/LICENSE`} target="_blank" rel="noreferrer" className={ext}>License (MIT)</a></li>
          </Col>

          <Col title="Use responsibly">
            <li className="text-sm leading-relaxed text-[#635d80]">
              For <strong className="text-violetx-ink">authorized</strong> security testing only:
              bug bounty scope, signed pentest, or your own assets.
            </li>
          </Col>
        </div>

        <div className="mt-8 flex flex-col items-center justify-between gap-3 border-t border-[#f0edf9] pt-6 text-xs text-[#9691ac] sm:flex-row">
          <p>© {new Date().getFullYear()} Vantis · Free &amp; open-source under the MIT License.</p>
          <p className="flex items-center gap-1.5">
            <span>Made by</span>
            <a
              href={AUTHOR}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 font-semibold text-violetx transition hover:text-violetx-ink"
            >
              <svg viewBox="0 0 24 24" className="h-4 w-4 shrink-0" fill="currentColor" aria-hidden>
                <path d="M20.45 20.45h-3.56v-5.57c0-1.33-.02-3.04-1.85-3.04-1.85 0-2.14 1.45-2.14 2.94v5.67H9.34V9h3.42v1.56h.05c.48-.9 1.64-1.85 3.37-1.85 3.6 0 4.27 2.37 4.27 5.46v6.28zM5.34 7.43a2.07 2.07 0 110-4.14 2.07 2.07 0 010 4.14zM7.12 20.45H3.56V9h3.56v11.45zM22.22 0H1.77C.79 0 0 .77 0 1.73v20.54C0 23.22.79 24 1.77 24h20.45c.98 0 1.78-.78 1.78-1.73V1.73C24 .77 23.2 0 22.22 0z" />
              </svg>
              <span>Nathane Sebban</span>
            </a>
          </p>
        </div>
      </div>
    </footer>
  );
}
