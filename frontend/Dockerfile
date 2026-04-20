# ── Stage 1: build ───────────────────────────────────────────
FROM node:22-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --silent

COPY . .
RUN npm run build

# ── Stage 2: serve ───────────────────────────────────────────
FROM nginx:1.27-alpine

# SPA config (injected below) + proxy to API
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Built assets
COPY --from=builder /app/dist /usr/share/nginx/html

EXPOSE 5173

CMD ["nginx", "-g", "daemon off;"]
