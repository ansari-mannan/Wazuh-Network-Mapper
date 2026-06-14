import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The browser only ever talks to /api/*; Vite proxies that to the Express
// backend in dev so there's no CORS dance and no bundled graph.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": "http://localhost:3001",
    },
  },
});
