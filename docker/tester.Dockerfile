# syntax=docker/dockerfile:1.7
FROM golang:1.26.5-alpine AS build
WORKDIR /src
COPY go /src
RUN CGO_ENABLED=0 go build -o /out/blindportd ./cmd/blindportd

FROM python:3.14-slim
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        curl ca-certificates iproute2 dnsutils openssl \
        build-essential libffi-dev pkg-config \
 && rm -rf /var/lib/apt/lists/*
COPY backend/requirements-dev.txt /tmp/requirements-dev.txt
RUN pip install --require-hashes -r /tmp/requirements-dev.txt
COPY --from=build /out/blindportd /usr/local/bin/blindportd
