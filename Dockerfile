FROM node:22-bookworm-slim AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci

FROM deps AS build
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:22-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    TANOD_AUDIT_FILE=/data/audit.jsonl \
    TANOD_PRIVATE_KEY_FILE=/data/ed25519-private.pem \
    TANOD_PUBLIC_KEY_FILE=/data/ed25519-public.pem
COPY package*.json ./
RUN npm ci --omit=dev \
  && groupadd --system tanod \
  && useradd --system --gid tanod --home-dir /app --shell /usr/sbin/nologin tanod \
  && mkdir -p /data \
  && chown -R tanod:tanod /app /data
COPY --from=build --chown=tanod:tanod /app/dist ./dist
COPY --chown=tanod:tanod examples ./examples
COPY --chown=tanod:tanod db ./db
USER tanod
EXPOSE 8787
CMD ["node", "dist/src/index.js", "server"]
