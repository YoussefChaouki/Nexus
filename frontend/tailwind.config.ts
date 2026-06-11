import type { Config } from "tailwindcss";

// Single source of truth for design tokens — mirrors Design System.html.
// Surfaces / ink / agents / severity / accent → mapped to Tailwind colors
// so the rest of the codebase consumes them via class names.
const config: Config = {
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./lib/**/*.{ts,tsx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        bg: {
          DEFAULT: "#0a0c10",
          deep: "#06080b",
          card: "#0e1116",
          elev: "#11141a",
        },
        border: {
          DEFAULT: "#1a1f28",
          emph: "#2a323e",
        },
        fg: {
          DEFAULT: "#d4d8de",
          muted: "#7a8290",
          faint: "#4a525e",
        },
        agent: {
          planner: "#c4a8ff",
          researcher: "#7eb8ff",
          analyst: "#5ed4c1",
          critic: "#ff8a7e",
          writer: "#9ee87a",
        },
        sev: {
          critical: "#ff5252",
          high: "#ffa64d",
          medium: "#ffd54d",
          low: "#66d9a0",
        },
        accent: "#5ed4c1",
      },
      fontFamily: {
        mono: [
          "var(--font-mono)",
          "JetBrains Mono",
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "monospace",
        ],
      },
      fontSize: {
        // Type scale from Design System.html §02
        display: ["36px", { lineHeight: "41px", letterSpacing: "-0.01em", fontWeight: "500" }],
        h1: ["28px", { lineHeight: "34px", fontWeight: "500" }],
        h2: ["20px", { lineHeight: "26px", fontWeight: "500" }],
        h3: ["16px", { lineHeight: "22px", fontWeight: "500" }],
        body: ["13px", { lineHeight: "21px", fontWeight: "400" }],
        small: ["12px", { lineHeight: "18px", fontWeight: "400" }],
        caption: ["10.5px", { lineHeight: "16px", letterSpacing: "0.14em", fontWeight: "500" }],
      },
      letterSpacing: {
        caption: "0.14em",
        wider: "0.1em",
        widest: "0.16em",
      },
      spacing: {
        // Mirrors --s-* tokens. Tailwind's default scale is kept for
        // generic utilities; these extras let us use the exact rhythm.
        px: "0.0625rem",
        "ds-1": "0.25rem",
        "ds-2": "0.5rem",
        "ds-3": "0.75rem",
        "ds-4": "1rem",
        "ds-5": "1.5rem",
        "ds-6": "2rem",
        "ds-7": "3rem",
        "ds-8": "4rem",
        "ds-9": "6rem",
      },
      borderRadius: {
        // The system forbids non-zero radius on cards. Keep the scale flat.
        none: "0",
        DEFAULT: "0",
      },
      keyframes: {
        pulse: {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.35" },
        },
        blink: {
          "50%": { opacity: "0" },
        },
        scanline: {
          "0%": { top: "-2%", opacity: "0" },
          "10%": { opacity: "1" },
          "90%": { opacity: "1" },
          "100%": { top: "102%", opacity: "0" },
        },
        pipeflow: {
          "0%": { transform: "translate(-100%, -50%)", opacity: "0" },
          "20%": { opacity: "0.6" },
          "80%": { opacity: "0.6" },
          "100%": { transform: "translate(100%, -50%)", opacity: "0" },
        },
        blip: {
          "0%": { left: "-10px", opacity: "0" },
          "10%": { opacity: "1" },
          "90%": { opacity: "1" },
          "100%": { left: "calc(100% + 10px)", opacity: "0" },
        },
        "rail-flow": {
          "0%": { backgroundPosition: "0 0" },
          "100%": { backgroundPosition: "16px 0" },
        },
        "bar-grow": {
          from: { transform: "scaleX(0)" },
          to: { transform: "scaleX(1)" },
        },
      },
      animation: {
        "pulse-soft": "pulse 1.6s ease-in-out infinite",
        blink: "blink 1.1s steps(2) infinite",
        scanline: "scanline 9s linear infinite",
        pipeflow: "pipeflow 4.5s linear infinite",
        blip: "blip 4.5s linear infinite",
        "rail-flow": "rail-flow 0.9s linear infinite",
        "bar-grow": "bar-grow 0.7s cubic-bezier(0.2, 0.65, 0.25, 1) both",
      },
    },
  },
  plugins: [],
};

export default config;
