import type { Config } from "tailwindcss";
const config: Config = {
  content: ["./app/**/*.{js,ts,jsx,tsx,mdx}", "./components/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: { extend: { colors: { brand: "#0f172a", accent: "#f59e0b" }, fontFamily: { mono: ["JetBrains Mono", "Consolas", "monospace"], display: ["Inter", "Arial", "sans-serif"] } } },
  plugins: [],
};
export default config;
