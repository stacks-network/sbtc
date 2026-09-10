import { defineConfig } from "vite";
import { fileURLToPath } from "node:url";

export default defineConfig({
  // Relative asset URLs work both locally and at the GitHub Pages /sbtc path.
  base: "./",
  build: {
    outDir: "dist",
    rollupOptions: {
      input: {
        index: fileURLToPath(new URL("./index.html", import.meta.url)),
        about: fileURLToPath(new URL("./about.html", import.meta.url)),
      },
    },
  },
});
