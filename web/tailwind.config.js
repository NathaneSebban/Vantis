/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // Severity accents — the only saturated colors in the palette.
        severity: {
          critical: "#991b1b",
          high: "#dc2626",
          medium: "#ea580c",
          low: "#2563eb",
          info: "#6b7280",
        },
      },
      fontFamily: {
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
      },
    },
  },
  plugins: [],
};
