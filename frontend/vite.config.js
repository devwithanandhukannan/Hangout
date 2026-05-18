import path from "path";
import { fileURLToPath } from "url";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import dotenv from "dotenv";

dotenv.config();

const API_BASE_URL = process.env.VITE_API_BASE_URL || "https://hangout-all4.onrender.com/";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
    },
  },
  server: {
    port: 5173,
    allowedHosts: true,
    proxy: {
      "/api": {
        target: API_BASE_URL,
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
      "/socket.io": {
        target: API_BASE_URL,
        changeOrigin: true,
        ws: true,
      },
      "/profile": {
        target: API_BASE_URL,
        changeOrigin: true,
        rewrite: (path) => path.replace(/:8000/, ""),
      },
    },
  },
});