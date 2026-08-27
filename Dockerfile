ARG VERSION=dev
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
ARG CLOUDFLARED_VERSION=2026.7.3

FROM cloudflare/cloudflared:${CLOUDFLARED_VERSION} AS cloudflared

FROM node:22-bookworm-slim AS dependencies
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 make g++ \
    && rm -rf /var/lib/apt/lists/*
COPY package*.json ./
RUN if [ -f package-lock.json ]; then npm ci --omit=dev --no-fund; else npm install --omit=dev --no-fund; fi \
    && npm audit --omit=dev --audit-level=high

FROM node:22-bookworm-slim
ARG VERSION
ARG VCS_REF
ARG BUILD_DATE
LABEL org.opencontainers.image.title="SHAM" \
      org.opencontainers.image.description="Self-hosted control plane for static sites and managed Node.js applications" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$VCS_REF" \
      org.opencontainers.image.created="$BUILD_DATE" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"
ENV NODE_ENV=production \
    SHAM_HOST=0.0.0.0 \
    SHAM_PORT=8080 \
    SHAM_DATA_PATH=/data
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      awscli ca-certificates certbot docker.io git libcap2-bin openssh-client \
      python3-certbot-dns-cloudflare restic tar tini \
    && setcap cap_net_bind_service=+ep "$(readlink -f "$(command -v node)")" \
    && setcap cap_net_bind_service=+ep "$(readlink -f "$(command -v python3)")" \
    && rm -rf /var/lib/apt/lists/*
COPY --from=dependencies /app/node_modules ./node_modules
COPY --from=cloudflared /usr/local/bin/cloudflared /usr/local/bin/cloudflared
COPY package.json ./
COPY src ./src
COPY runtime-agent ./runtime-agent
COPY public ./public
COPY examples ./examples
COPY README.md LICENSE ./
RUN mkdir -p /data && chown -R node:node /data /app
USER node
VOLUME ["/data"]
EXPOSE 8080 80 443
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD node -e "fetch('http://127.0.0.1:8080/api/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "src/bootstrap.js"]
