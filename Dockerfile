FROM registry.access.redhat.com/ubi9/nodejs-22-minimal@sha256:97a1b1d1c805cd6f99505edf7d137a752639cab02327f176533ba96de65b414c AS deps
WORKDIR /opt/app-root/src
COPY --chown=1001:0 package*.json ./
RUN npm ci

FROM deps AS build
COPY --chown=1001:0 tsconfig.json ./
COPY --chown=1001:0 src ./src
RUN npm run build

FROM registry.access.redhat.com/ubi9/nodejs-22-minimal@sha256:97a1b1d1c805cd6f99505edf7d137a752639cab02327f176533ba96de65b414c AS runtime
WORKDIR /opt/app-root/src
ENV NODE_ENV=production \
    TANOD_AUDIT_FILE=/data/audit.jsonl \
    TANOD_PRIVATE_KEY_FILE=/data/ed25519-private.pem \
    TANOD_PUBLIC_KEY_FILE=/data/ed25519-public.pem
COPY --chown=1001:0 package*.json ./
RUN npm ci --omit=dev
USER 0
RUN mkdir -p /data \
  && chown -R 1001:0 /data /opt/app-root/src \
  && chmod -R g=u /data /opt/app-root/src
COPY --from=build --chown=1001:0 /opt/app-root/src/dist ./dist
COPY --chown=1001:0 examples ./examples
COPY --chown=1001:0 db ./db
USER 1001
EXPOSE 8787
CMD ["node", "dist/src/index.js", "server"]
