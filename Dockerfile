# Pinned by digest (node:22-alpine, index digest read 2026-09-28), so a rebuild
# gets exactly this base and not whatever the tag points at that day. To move
# it: `docker buildx imagetools inspect node:22-alpine`, copy the top Digest.
FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402

WORKDIR /app

COPY package.json package-lock.json ./
# No dependency has an install script (package-lock: 0 hasInstallScript), so
# none is allowed to run.
RUN npm ci --ignore-scripts

COPY tsconfig.json ./
COPY src/ ./src/

RUN npm run build && npm prune --omit=dev --ignore-scripts && npm cache clean --force

# Production mode from here on: Express hides error detail, and the app's own
# error handler never sends a stack trace either way.
ENV NODE_ENV=production

# The files stay root-owned and read-only to the process, which runs as the
# image's unprivileged `node` user (uid 1000). It writes nothing but /tmp,
# which compose mounts as a tmpfs because the root filesystem is read-only.
USER node

EXPOSE 3459

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:3459/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]

CMD ["node", "dist/index.js"]
