# syntax=docker/dockerfile:1.7
FROM --platform=$BUILDPLATFORM oven/bun:1.3.11@sha256:0733e50325078969732ebe3b15ce4c4be5082f18c4ac1a0f0ca4839c2e4e42a7 AS nwc-helper-build

ARG TARGETARCH
WORKDIR /build
COPY tools/nwc-helper/package.json tools/nwc-helper/bun.lock ./
RUN bun install --frozen-lockfile --production
COPY tools/nwc-helper/src ./src
RUN case "$TARGETARCH" in \
        amd64) bun_target=bun-linux-x64 ;; \
        arm64) bun_target=bun-linux-arm64 ;; \
        *) echo "unsupported NWC helper architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && bun build --compile --minify --target="$bun_target" \
        --outfile /out/blindport-nwc-helper src/main.ts

FROM --platform=$BUILDPLATFORM oven/bun:1.3.11@sha256:0733e50325078969732ebe3b15ce4c4be5082f18c4ac1a0f0ca4839c2e4e42a7 AS clink-helper-build

ARG TARGETARCH
WORKDIR /build
COPY tools/clink-helper/package.json tools/clink-helper/bun.lock ./
RUN bun install --frozen-lockfile --production
COPY tools/clink-helper/src ./src
RUN case "$TARGETARCH" in \
        amd64) bun_target=bun-linux-x64 ;; \
        arm64) bun_target=bun-linux-arm64 ;; \
        *) echo "unsupported CLINK helper architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && bun build --compile --minify --target="$bun_target" \
        --outfile /out/blindport-clink-helper src/main.ts

FROM python:3.14-slim@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6 AS build

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install locked dependencies first to enable layer caching.
COPY backend/requirements.txt /app/backend/requirements.txt
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --require-hashes -r /app/backend/requirements.txt

COPY backend/pyproject.toml backend/README.md /app/backend/
COPY backend/src /app/backend/src
RUN /opt/venv/bin/pip install --no-deps /app/backend

FROM python:3.14-slim@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6 AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH=/opt/venv/bin:$PATH

RUN groupadd --gid 10001 blindport \
    && useradd --uid 10001 --gid blindport --no-create-home --shell /usr/sbin/nologin blindport \
    && mkdir -p /data /var/lib/blindport/ca \
    && chown -R blindport:blindport /data /var/lib/blindport

WORKDIR /app
COPY --from=build /opt/venv /opt/venv
COPY --from=nwc-helper-build --chmod=0555 /out/blindport-nwc-helper /usr/local/bin/blindport-nwc-helper
COPY --from=clink-helper-build --chmod=0555 /out/blindport-clink-helper /usr/local/bin/blindport-clink-helper
COPY --chmod=0555 docker/backend-entrypoint.sh /usr/local/bin/backend-entrypoint

USER 10001:10001

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=15s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health/ready', timeout=12)"]
ENTRYPOINT ["backend-entrypoint"]
CMD ["uvicorn", "blindport.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips=127.0.0.1,::1", "--no-access-log"]
