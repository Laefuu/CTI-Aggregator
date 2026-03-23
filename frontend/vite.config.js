import { defineConfig } from "vite"
import react from "@vitejs/plugin-react"

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/auth":      "http://localhost:8000",
      "/sources":   "http://localhost:8000",
      "/objects":   "http://localhost:8000",
      "/perimeters":"http://localhost:8000",
      "/alerts":    "http://localhost:8000",
      "/metrics":   "http://localhost:8000",
    },
  },
  build: { outDir: "../frontend/dist" },
})
