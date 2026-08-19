FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/cpa-log-bridge ./cmd/cpa-log-bridge
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/cpa-log-bridge ./cmd/cpa-log-bridge

FROM alpine:3.23

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S -g 65532 bridge \
    && adduser -S -D -H -u 65532 -G bridge bridge

COPY --from=builder /out/cpa-log-bridge /usr/local/bin/cpa-log-bridge

USER 65532:65532
EXPOSE 8080
ENV TZ=UTC

HEALTHCHECK --interval=30s --timeout=8s --start-period=10s --retries=3 \
    CMD /usr/local/bin/cpa-log-bridge healthcheck

ENTRYPOINT ["/usr/local/bin/cpa-log-bridge"]
