import { defineConfig } from "tsdown";

export default defineConfig({
  entry: [
    "src/index.ts",
    "src/client/index.ts",
    "src/react/index.ts",
    "src/server/index.ts",
    "src/server/hono.ts",
    "src/server/express.ts",
  ],
  format: "esm",
  dts: true,
  // The server entries use only fetch + WebCrypto (via jose), so the package
  // is edge/runtime-neutral. React/Hono/Express are optional peers.
  platform: "neutral",
  target: "es2022",
  external: ["react", "react/jsx-runtime", "hono", "express", "jose"],
});
