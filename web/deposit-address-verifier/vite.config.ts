import { defineConfig } from 'vite'

export default defineConfig({
  // Relative asset URLs work both locally and at the GitHub Pages /sbtc path.
  base: './',
  build: { outDir: 'dist' },
})
