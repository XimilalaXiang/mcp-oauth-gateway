# MCP OAuth Gateway

A unified OAuth 2.1 gateway for self-hosted MCP servers. Connect all your MCP servers to Claude.ai, Claude Desktop, and other OAuth-compatible MCP clients through a single authentication endpoint.

Built with Go. Docker image ~15MB, runtime memory ~2MB. Single binary, zero external dependencies.

## Why

Claude.ai requires full OAuth 2.1 + PKCE for remote MCP server connections. Instead of implementing OAuth in every MCP server, this gateway handles authentication centrally and proxies requests to your backends.

## Architecture

```
Claude.ai / Claude Desktop / Claude Code
  → MCP OAuth Gateway (OAuth 2.1 + PKCE)
    → /mcp/blinko/*   → blinko-mcp:8080
    → /mcp/wallos/*   → wallos-mcp:8080
    → /mcp/freshrss/* → freshrss-mcp:8080
    → /mcp/ech0/*     → ech0-mcp:8080
```

## Features

- **OAuth 2.1 compliant** — PKCE (S256), Dynamic Client Registration (RFC 7591), Protected Resource Metadata (RFC 9728), Authorization Server Metadata (RFC 8414)
- **CIMD support** — Client ID Metadata Document for registration-free onboarding
- **Multi-backend** — Route to any number of MCP servers via path-based routing
- **Minimal login** — Simple password-based consent screen for self-hosted use
- **Backend-agnostic** — Works with any MCP server (SSE, Streamable HTTP, stdio via adapter)
- **JWT tokens** — Short-lived access tokens with configurable TTL

## Quick Start

### Docker Compose

```yaml
services:
  mcp-oauth-gateway:
    image: ghcr.io/ximilalaxiang/mcp-oauth-gateway:latest
    container_name: mcp-oauth-gateway
    restart: unless-stopped
    ports:
      - "8800:8800"
    environment:
      - GATEWAY_BASE_URL=https://mcp-gateway.yourdomain.com
      - GATEWAY_PASSWORD=your-strong-password
      - GATEWAY_JWT_SECRET=random-32-character-secret-here
    volumes:
      - ./config.yaml:/etc/mcp-oauth-gateway/config.yaml:ro
```

### Configuration

Create `config.yaml`:

```yaml
server:
  port: 8800
  base_url: https://mcp-gateway.yourdomain.com

auth:
  password: your-login-password
  jwt_secret: random-32-char-string
  token_ttl: 24h

backends:
  blinko:
    name: Blinko Notes
    upstream: http://blinko-mcp:8080
    transport: sse
    auth_header: "Bearer your-blinko-token"
  wallos:
    name: Wallos Subscriptions
    upstream: http://wallos-mcp:8080
    transport: sse
    auth_header: "Bearer your-wallos-token"
  freshrss:
    name: FreshRSS Reader
    upstream: http://freshrss-mcp:8080
    transport: sse
    auth_header: "Bearer your-freshrss-token"
```

### Environment Variables

Environment variables override config file values:

| Variable | Description | Default |
|----------|-------------|---------|
| `GATEWAY_PORT` | Server port | `8800` |
| `GATEWAY_BASE_URL` | Public URL of the gateway | — (required) |
| `GATEWAY_PASSWORD` | Login password for authorization | — (required) |
| `GATEWAY_JWT_SECRET` | JWT signing secret (min 16 chars) | — (required) |

## Connect from Claude.ai

1. Go to **Settings → Connectors → Add Connector**
2. Enter URL: `https://mcp-gateway.yourdomain.com/mcp/blinko/sse`
3. Claude.ai will discover OAuth endpoints automatically
4. You'll see a login page — enter your password
5. Done! All Blinko MCP tools are now available

Repeat for each backend (`/mcp/wallos/sse`, `/mcp/freshrss/sse`, etc.)

## OAuth Flow

```
1. Claude requests /mcp/blinko/sse
2. Gateway returns 401 + WWW-Authenticate header
3. Claude discovers /.well-known/oauth-protected-resource
4. Claude discovers /.well-known/oauth-authorization-server
5. Claude registers via POST /register (DCR)
6. Claude redirects user to GET /authorize
7. User enters password on login page
8. Gateway redirects back to Claude with authorization code
9. Claude exchanges code + PKCE verifier at POST /token
10. Claude receives JWT access token
11. All subsequent requests include Bearer token
12. Gateway validates JWT and proxies to backend
```

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `/.well-known/oauth-protected-resource` | RFC 9728 Protected Resource Metadata |
| `/.well-known/oauth-authorization-server` | RFC 8414 Authorization Server Metadata |
| `/register` | RFC 7591 Dynamic Client Registration |
| `/authorize` | OAuth authorization endpoint |
| `/token` | OAuth token endpoint |
| `/mcp/{backend}/*` | Reverse proxy to backend MCP servers |
| `/health` | Health check |

## Build

```bash
# Local build
go build -o mcp-oauth-gateway .

# Docker build
docker build -t mcp-oauth-gateway:latest .
```

## Reverse Proxy (Nginx/Caddy)

The gateway must be behind HTTPS for OAuth to work. Example Caddy config:

```
mcp-gateway.yourdomain.com {
    reverse_proxy localhost:8800
}
```

## Security Notes

- All OAuth endpoints require HTTPS in production (enforced by Claude.ai)
- PKCE S256 is mandatory — plain method is rejected
- JWT tokens are short-lived (configurable, default 24h)
- Dynamic client registrations are automatically cleaned up after 7 days
- Authorization codes expire after 10 minutes and are single-use
- Password comparison uses constant-time comparison to prevent timing attacks

## License

MIT
