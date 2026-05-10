import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ command }) => ({
  plugins: [react()],
  optimizeDeps:
    command === "serve"
      ? {
          disabled: true,
          noDiscovery: true,
          include: [],
        }
      : undefined,
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:5000",
        changeOrigin: true,
      },
      "/admin": {
        target: "http://127.0.0.1:5000",
        changeOrigin: true,
      },
    },
  },
}));
