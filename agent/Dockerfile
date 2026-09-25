FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -tags timetzdata -ldflags="-s -w" -o /out/agent ./agent/cmd/main.go

FROM alpine:3.19
ARG VERSION=dev
LABEL org.opencontainers.image.title="flowlens-agent" \
      org.opencontainers.image.description="FlowLens traffic collection agent" \
      org.opencontainers.image.version="${VERSION}"
# No package installs: alpine ships the CA bundle and the binary embeds the
# time zone database (timetzdata), so the image builds without a mirror.
RUN addgroup -S flowlens && adduser -S -G flowlens -H flowlens
WORKDIR /app
COPY --from=builder /out/agent /app/agent
# Gateway-log mode only needs read access to the log file. eBPF mode needs
# host networking and CAP_BPF/CAP_SYS_ADMIN and must run as root instead.
USER flowlens
ENTRYPOINT ["./agent"]
CMD ["-config", "/etc/flowlens/agent-config.yaml"]
