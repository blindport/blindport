# syntax=docker/dockerfile:1.7
FROM golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
ARG VERSION=dev

WORKDIR /src
COPY go/go.mod go/go.sum /src/
RUN go mod download
COPY go /src
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -buildid=" -o /out/blindport-relay ./cmd/blindport-relay \
 && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -buildid= -X main.version=${VERSION}" -o /out/blindportd ./cmd/blindportd

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS relay
RUN apk add --no-cache ca-certificates iproute2 \
 && addgroup -g 10001 -S blindport \
 && adduser -u 10001 -S -D -H -G blindport blindport
COPY --from=build /out/blindport-relay /usr/local/bin/blindport-relay
COPY --chmod=0555 docker/relay-entrypoint.sh /usr/local/bin/relay-entrypoint
USER 10001:10001
EXPOSE 443 5443 9090
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["wget", "-qO-", "http://127.0.0.1:9090/readyz"]
ENTRYPOINT ["relay-entrypoint"]
CMD ["-control", ":5443"]

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS blindportd
RUN apk add --no-cache ca-certificates \
 && addgroup -g 10001 -S blindport \
 && adduser -u 10001 -S -D -H -G blindport blindport \
 && install -d -o blindport -g blindport -m 0700 /var/lib/blindport
COPY --from=build /out/blindportd /usr/local/bin/blindportd
USER 10001:10001
ENV BLINDPORT_STATE_DIR=/var/lib/blindport
ENTRYPOINT ["blindportd"]
