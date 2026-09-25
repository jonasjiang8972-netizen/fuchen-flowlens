FROM golang:1.25-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o platform ./platform/cmd/main.go

FROM alpine:3.19
RUN apk --no-cache add ca-certificates tzdata \
    && addgroup -S flowlens && adduser -S -G flowlens -H flowlens
WORKDIR /app
COPY --from=builder /app/platform .
USER flowlens

EXPOSE 8080
ENTRYPOINT ["./platform"]
