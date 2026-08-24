/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        ink: {
          950: "#050308",
          900: "#0a0712",
          800: "#110b1f",
          700: "#181128",
        },
        neon: {
          violet: "#a855f7",
          bright: "#c084fc",
          indigo: "#6366f1",
          magenta: "#d946ef",
          cyan: "#22d3ee",
        },
        // Severity accents — brightened so they glow on the near-black ground.
        severity: {
          critical: "#ff2d55",
          high: "#ff5470",
          medium: "#ff9f43",
          low: "#3b82f6",
          info: "#8b8299",
        },
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
      },
      boxShadow: {
        neon: "0 0 0 1px rgba(168,85,247,0.35), 0 0 20px -2px rgba(168,85,247,0.45)",
        "neon-soft": "0 0 30px -8px rgba(168,85,247,0.55)",
        glow: "0 0 24px -6px rgba(192,132,252,0.7)",
        panel: "0 1px 0 0 rgba(255,255,255,0.05) inset, 0 20px 40px -24px rgba(0,0,0,0.8)",
      },
      keyframes: {
        drift: {
          "0%": { transform: "translate3d(-4%, -2%, 0) rotate(0deg) scale(1.1)" },
          "33%": { transform: "translate3d(6%, 4%, 0) rotate(40deg) scale(1.25)" },
          "66%": { transform: "translate3d(-3%, 6%, 0) rotate(-30deg) scale(1.15)" },
          "100%": { transform: "translate3d(-4%, -2%, 0) rotate(0deg) scale(1.1)" },
        },
        pulseglow: {
          "0%, 100%": { opacity: "0.55" },
          "50%": { opacity: "1" },
        },
        scanline: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100%)" },
        },
        shimmer: {
          "0%": { backgroundPosition: "-200% 0" },
          "100%": { backgroundPosition: "200% 0" },
        },
      },
      animation: {
        drift: "drift 26s ease-in-out infinite",
        "drift-slow": "drift 40s ease-in-out infinite reverse",
        pulseglow: "pulseglow 3.5s ease-in-out infinite",
        scanline: "scanline 4s linear infinite",
        shimmer: "shimmer 2.2s linear infinite",
      },
    },
  },
  plugins: [],
};
