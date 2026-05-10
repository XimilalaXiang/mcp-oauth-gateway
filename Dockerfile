FROM golang:1.23-alpine AS builder
WORKDIR /build
COPY go.mod ./
RUN go mod download || true
COPY . .
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /mcp-oauth-gateway .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /mcp-oauth-gateway /usr/local/bin/mcp-oauth-gateway
COPY config.yaml /etc/mcp-oauth-gateway/config.yaml
ENTRYPOINT ["mcp-oauth-gateway", "-config", "/etc/mcp-oauth-gateway/config.yaml"]
