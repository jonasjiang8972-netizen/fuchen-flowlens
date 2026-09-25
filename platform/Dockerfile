FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -tags timetzdata -ldflags="-s -w" -o /out/platform ./platform/cmd/main.go

FROM alpine:3.19
ARG VERSION=dev
LABEL org.opencontainers.image.title="flowlens-platform" \
      org.opencontainers.image.description="FlowLens API security platform" \
      org.opencontainers.image.version="${VERSION}"
# No package installs: alpine ships the CA bundle and the binary embeds the
# time zone database (timetzdata), so the image builds without a mirror.
RUN addgroup -S flowlens && adduser -S -G flowlens -H flowlens
WORKDIR /app
COPY --from=builder /out/platform /app/platform
USER flowlens
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=5 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/api/v1/health || exit 1
ENTRYPOINT ["./platform"]
