# apps/web/Dockerfile
FROM node:lts-alpine AS builder
WORKDIR /app

# No package-lock.json is committed, so `npm ci` would fail. Prefer the
# lockfile when one is present (reproducible builds), otherwise fall back to
# `npm install`. `COPY package*.json` also tolerates a missing lockfile.
COPY package*.json ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi

COPY . .

# Point the SPA at the API container by hostname on the actilp-net bridge.
# Note: `COPY . .` also brings in apps/web/.env, and Vite ranks .env files above
# this ENV/ARG — so the value below must match apps/web/.env, or edit that file.
ARG VITE_API_URL=http://localhost:8080/api/v1
ENV VITE_API_URL=$VITE_API_URL
RUN npm run build

FROM node:lts-alpine
WORKDIR /app
RUN npm install -g serve

COPY --from=builder /app/dist ./dist

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -q --spider http://localhost:3000/ || exit 1

CMD ["serve", "-s", "dist", "-l", "3000"]
