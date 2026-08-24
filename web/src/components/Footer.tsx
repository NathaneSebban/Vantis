import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import wordmark from "../assets/wordmark.png";

const REPO = "https://github.com/NathaneSebban/Vantis";
const AUTHOR = "https://github.com/NathaneSebban";

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
              Modular vulnerability scanner — recon, web and CVE detection.
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
              For <strong className="text-violetx-ink">authorized</strong> security testing only —
              bug bounty scope, signed pentest, or your own assets.
            </li>
          </Col>
        </div>

        <div className="mt-8 flex flex-col items-center justify-between gap-3 border-t border-[#f0edf9] pt-6 text-xs text-[#9691ac] sm:flex-row">
          <p>© {new Date().getFullYear()} Vantis · Free &amp; open-source under the MIT License.</p>
          <p>
            Made by{" "}
            <a
              href={AUTHOR}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 font-semibold text-violetx transition hover:text-violetx-ink"
            >
              <svg viewBox="0 0 16 16" className="h-3.5 w-3.5" fill="currentColor" aria-hidden>
                <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0016 8c0-4.42-3.58-8-8-8z" />
              </svg>
              Nathane Sebban
            </a>
          </p>
        </div>
      </div>
    </footer>
  );
}
