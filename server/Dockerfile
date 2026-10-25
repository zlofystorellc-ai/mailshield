# Build context is the repo root (see docker-compose.yml) so /admin and privacy-policy.md are included.
FROM node:20-alpine
WORKDIR /app

COPY server/package*.json server/
RUN cd server && npm install --omit=dev --no-audit --no-fund

COPY server server
COPY admin admin
COPY privacy-policy.md ./

ENV NODE_ENV=production
EXPOSE 3000
USER node
HEALTHCHECK --interval=30s --timeout=5s CMD wget -qO- http://127.0.0.1:3000/healthz || exit 1
CMD ["node", "server/src/index.js"]
