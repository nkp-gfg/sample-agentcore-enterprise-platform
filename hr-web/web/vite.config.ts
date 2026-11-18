import path from "node:path";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const rootDir = import.meta.dirname;

const bff = "http://127.0.0.1:8080";

export default defineConfig({
  base: "/",
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(rootDir, "./src"),
    },
  },
  build: {
    outDir: "dist",
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes("node_modules/@a2ui/")) return "a2ui";
          if (id.includes("node_modules/react-markdown") || id.includes("node_modules/mdast") || id.includes("node_modules/micromark")) {
            return "markdown";
          }
          if (id.includes("node_modules/react-dom") || id.includes("node_modules/react/")) return "react";
        },
      },
    },
  },
  server: {
    proxy: {
      "/api": bff,
      "/auth": bff,
      "/invocations": bff,
      "/config.json": bff,
      "/healthz": bff,
    },
  },
});
