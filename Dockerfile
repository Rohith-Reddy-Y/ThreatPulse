# ThreatPulse — production container
# Node + SQLite in a single image. Data persists on a mounted volume at /data.
FROM node:20-bookworm-slim

# Build tools for better-sqlite3's native binding (used only if no prebuilt binary matches)
RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 make g++ ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies first (better layer caching)
COPY package*.json ./
RUN npm ci --omit=dev

# App source
COPY . .

ENV NODE_ENV=production
ENV PORT=3000
ENV DB_PATH=/data/threatpulse.db

EXPOSE 3000

# The volume mount point; the app auto-detects /data and stores its SQLite DB there.
VOLUME ["/data"]

CMD ["node", "server.js"]
