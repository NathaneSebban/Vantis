/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Deep violet family sampled from the logo (no pink/magenta).
        violetx: {
          ink: "#241a52",
          deep: "#3a2a8c",
          DEFAULT: "#4c2fbf",
          bright: "#6d4fe0",
          soft: "#efecfb",
          tint: "#f6f4fd",
        },
        // Semantic severity colors — kept distinguishable but pink-free
        // (true reds/oranges, indigo/slate), readable on a white ground.
        severity: {
          critical: "#a80f22",
          high: "#dc2626",
          medium: "#e8590c",
          low: "#4f46e5",
          info: "#64748b",
        },
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
      },
      boxShadow: {
        glow: "0 12px 30px -8px rgba(76,47,191,0.55)",
        "glow-soft": "0 10px 26px -12px rgba(76,47,191,0.4)",
      },
      keyframes: {
        drift: {
          "0%": { transform: "translate3d(-4%, -2%, 0) rotate(0deg) scale(1.1)" },
          "33%": { transform: "translate3d(6%, 4%, 0) rotate(40deg) scale(1.25)" },
          "66%": { transform: "translate3d(-3%, 6%, 0) rotate(-30deg) scale(1.15)" },
          "100%": { transform: "translate3d(-4%, -2%, 0) rotate(0deg) scale(1.1)" },
        },
        pulseglow: { "0%, 100%": { opacity: "0.5" }, "50%": { opacity: "1" } },
        shimmer: {
          "0%": { backgroundPosition: "-200% 0" },
          "100%": { backgroundPosition: "200% 0" },
        },
      },
      animation: {
        drift: "drift 28s ease-in-out infinite",
        pulseglow: "pulseglow 3s ease-in-out infinite",
        shimmer: "shimmer 2.2s linear infinite",
      },
    },
  },
  plugins: [],
};
