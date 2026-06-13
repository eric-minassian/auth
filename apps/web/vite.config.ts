import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The local Rust API (`cargo run --bin local`) listens here. Proxying keeps
// the SPA same-origin with the API in dev, matching production's cookie model.
const API_TARGET = "http://127.0.0.1:8787";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    // Browse at http://auth.localhost:5173 for same-site cookie parity.
    allowedHosts: ["auth.localhost", "localhost"],
    proxy: {
      "/api": API_TARGET,
      "/oauth": API_TARGET,
      "/.well-known": API_TARGET,
    },
  },
});
