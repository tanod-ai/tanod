FROM registry.access.redhat.com/ubi9/nodejs-22:1-1778648048 AS deps
WORKDIR /opt/app-root/src
COPY --chown=1001:0 package*.json ./
RUN npm ci

FROM deps AS build
COPY --chown=1001:0 tsconfig.json ./
COPY --chown=1001:0 src ./src
RUN npm run build

FROM deps AS prod-deps
RUN npm ci --omit=dev

FROM registry.access.redhat.com/ubi9/nodejs-22:1-1778648048 AS runtime
ARG TARGETARCH
ARG NODE_VERSION=22.22.2
WORKDIR /opt/app-root/src
ENV NODE_ENV=production \
    TANOD_AUDIT_FILE=/data/audit.jsonl \
    TANOD_PRIVATE_KEY_FILE=/data/ed25519-private.pem \
    TANOD_PUBLIC_KEY_FILE=/data/ed25519-public.pem \
    PATH=/usr/local/bin:/usr/bin:/bin
USER 0
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) node_arch=x64 ;; \
      arm64) node_arch=arm64 ;; \
      *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSLO "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${node_arch}.tar.xz"; \
    curl -fsSLO "https://nodejs.org/dist/v${NODE_VERSION}/SHASUMS256.txt"; \
    grep " node-v${NODE_VERSION}-linux-${node_arch}.tar.xz$" SHASUMS256.txt | sha256sum -c -; \
    tar -xJf "node-v${NODE_VERSION}-linux-${node_arch}.tar.xz" -C /usr/local --strip-components=1; \
    rm -f "node-v${NODE_VERSION}-linux-${node_arch}.tar.xz" SHASUMS256.txt; \
    rm -rf /usr/local/lib/node_modules /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
      /usr/local/include/node /usr/local/share/doc /usr/local/share/man; \
    removable="$(rpm -qa | grep -Ev '^(basesystem|filesystem|setup|glibc($|-)|libgcc-|libstdc\+\+-|tzdata-|ca-certificates-|crypto-policies($|-)|redhat-release-|rootfiles-|bash-|coreutils(|-single)-|libacl-|libattr-|libcap-|pcre2-|ncurses-base-|ncurses-libs-|gmp-|libselinux-|libsepol-)' || true)"; \
    if [ -n "$removable" ]; then rpm -e --nodeps --noscripts $removable || true; fi; \
    rm -rf /var/cache/dnf /var/cache/yum /var/tmp/* /tmp/* \
      /usr/share/doc /usr/share/man /usr/share/info /usr/src /usr/include; \
    mkdir -p /data /opt/app-root/src; \
    chown -R 1001:0 /data /opt/app-root/src; \
    chmod -R g=u /data /opt/app-root/src; \
    node --version
COPY --from=prod-deps --chown=1001:0 /opt/app-root/src/node_modules ./node_modules
COPY --from=build --chown=1001:0 /opt/app-root/src/dist ./dist
COPY --chown=1001:0 examples ./examples
COPY --chown=1001:0 db ./db
USER 1001
EXPOSE 8787
CMD ["node", "dist/src/index.js", "server"]
