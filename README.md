# 🔐 MCP AuthKit (Vercel Edition)

**OAuth for MCP servers, solved.**

A standalone Vercel Edge Function that implements the complete MCP OAuth specification so you don't have to. This is the Vercel-optimized variant of [MCP AuthKit](https://github.com/OpZero-sh/MCPAuthKit), built by [OpZero.sh](https://opzero.sh).

> **Status:** Production-ready reference implementation using Vercel Edge Functions + Turso (LibSQL)

-----

## The Problem

Every MCP server builder hits the same wall: the OAuth spec is *brutal*. You need RFC 9728 discovery, RFC 8414 metadata, RFC 7591 dynamic client registration, PKCE with S256, consent screens, token lifecycle management — all before your first tool call works.

We spent weeks fighting this in a Next.js codebase before realizing: **OAuth is not your product. Rip it out.**

## The Solution

AuthKit is a single Vercel Edge Function + Turso database that acts as a complete OAuth authorization server for any MCP server. Your MCP server points its `authorization_servers` to AuthKit, and the entire OAuth dance — registration, consent, tokens — happens here.

Your MCP server's only job: validate the Bearer token.

```json
// Your MCP server's /.well-known/oauth-protected-resource
{
  "resource": "https://your-mcp-server.com/mcp",
  "authorization_servers": ["https://your-authkit.vercel.app/api/auth"],
  "bearer_methods_supported": ["header"]
}
```

That's the entire integration.

## What It Implements

|Spec                                              |What                               |Status                     |
|--------------------------------------------------|-----------------------------------|---------------------------|
|[RFC 9728](https://www.rfc-editor.org/rfc/rfc9728)|Protected Resource Metadata        |✅ Auto-generated per server|
|[RFC 8414](https://www.rfc-editor.org/rfc/rfc8414)|Authorization Server Metadata      |✅                          |
|[RFC 7591](https://www.rfc-editor.org/rfc/rfc7591)|Dynamic Client Registration        |✅                          |
|OAuth 2.1                                         |Authorization code + PKCE (S256)   |✅                          |
|—                                                 |Token refresh                      |✅                          |
|—                                                 |Token revocation                   |✅                          |
|—                                                 |Consent screen with login/signup   |✅                          |
|—                                                 |Multi-tenant (multiple MCP servers)|✅                          |

## Architecture

```
Claude/ChatGPT          AuthKit (Vercel Edge + Turso)    Your MCP Server
     │                           │                           │
     │  POST /mcp (no token)     │                           │
     │──────────────────────────────────────────────────────►│
     │  401 + WWW-Authenticate   │                           │
     │◄──────────────────────────────────────────────────────│
     │                           │                           │
     │  GET /.well-known/oauth-protected-resource            │
     │──────────────────────────────────────────────────────►│
     │  { authorization_servers: ["https://authkit..."] }    │
     │◄──────────────────────────────────────────────────────│
     │                           │                           │
     │  GET /api/auth/.well-known/oauth-authorization-server │
     │─────────────────────────►│                           │
     │  { endpoints... }        │                           │
     │◄─────────────────────────│                           │
     │                           │                           │
     │  POST /api/auth/oauth/register                        │
     │─────────────────────────►│                           │
     │  { client_id }           │                           │
     │◄─────────────────────────│                           │
     │                           │                           │
     │  GET /api/auth/oauth/authorize                        │
     │─────────────────────────►│                           │
     │  [consent screen]        │                           │
     │◄─────────────────────────│                           │
     │  [user approves]         │                           │
     │─────────────────────────►│                           │
     │  302 → callback?code=xxx │                           │
     │◄─────────────────────────│                           │
     │                           │                           │
     │  POST /api/auth/oauth/token                           │
     │─────────────────────────►│                           │
     │  { access_token, ... }   │                           │
     │◄─────────────────────────│                           │
     │                           │                           │
     │  POST /mcp (Bearer mat_xxx)                           │
     │──────────────────────────────────────────────────────►│
     │                           │  GET /api/auth/oauth/userinfo │
     │                           │◄──────────────────────────│
     │                           │  { sub, email, name }     │
     │                           │─────────────────────────►│
     │  [tools response]         │                           │
     │◄──────────────────────────────────────────────────────│
```

## Quick Start

### Prerequisites

- [Vercel account](https://vercel.com/signup) (free hobby tier works)
- [Turso account](https://turso.tech) (free tier: 9 GB storage, 1 billion rows)
- [Turso CLI](https://docs.turso.tech/cli/installation) (`brew install tursodatabase/tap/turso` or `curl -sSfL https://get.tur.so/install.sh | bash`)
- Node.js 18+

### 1. Create Turso Database

```bash
# Login to Turso
turso auth login

# Create a new database
turso db create mcp-authkit

# Get the database URL
turso db show mcp-authkit --url
# → libsql://mcp-authkit-your-org.turso.io

# Create an auth token
turso db tokens create mcp-authkit
# → eyJ... (save this token!)
```

### 2. Deploy to Vercel

```bash
# Clone this repo
git clone https://github.com/OpZero-sh/mcp-authkit-vercel.git
cd mcp-authkit-vercel

# Install dependencies
npm install

# Set environment variables locally (for testing)
cp .env.example .env
# Edit .env with your Turso credentials and generate random strings for ADMIN_KEY and SALT

# Initialize the database schema
npm run db:init

# Deploy to Vercel
npm run deploy
```

During deployment, Vercel will prompt you to:
1. Link to your Vercel account
2. Set up the project
3. Configure production environment variables

Add these environment variables in the Vercel dashboard (Settings → Environment Variables):

```bash
TURSO_DATABASE_URL=libsql://mcp-authkit-your-org.turso.io
TURSO_AUTH_TOKEN=eyJ...
ADMIN_KEY=your-strong-random-admin-key
SALT=your-random-salt-string
```

Your AuthKit instance is live at `https://your-project.vercel.app/api/auth`.

### 3. Register Your MCP Server

```bash
curl -X POST https://your-authkit.vercel.app/api/auth/api/servers \
  -H "Authorization: Bearer YOUR_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My MCP Server",
    "resource_url": "https://my-mcp.com/mcp",
    "scopes": ["mcp:tools"]
  }'
```

Response:

```json
{
  "server_id": "srv_abc123...",
  "api_key": "sak_xyz789...",
  "prm_url": "https://your-authkit.vercel.app/api/auth/prm/srv_abc123...",
  "message": "Set authorization_servers in your PRM to point to this gateway."
}
```

### 4. Wire Up Your MCP Server

Update your MCP server's `/.well-known/oauth-protected-resource` endpoint:

```json
{
  "resource": "https://my-mcp.com/mcp",
  "authorization_servers": ["https://your-authkit.vercel.app/api/auth"],
  "bearer_methods_supported": ["header"]
}
```

## API Reference

All endpoints are prefixed with `/api/auth`:

|Method|Endpoint                                 |Description                    |
|------|-----------------------------------------|-------------------------------|
|`GET` |`/.well-known/oauth-authorization-server`|Authorization server metadata  |
|`POST`|`/oauth/register`                        |Dynamic client registration    |
|`GET` |`/oauth/authorize`                       |Authorization + consent UI     |
|`POST`|`/oauth/token`                           |Code → token exchange (PKCE)   |
|`POST`|`/oauth/revoke`                          |Token revocation               |
|`GET` |`/oauth/userinfo`                        |User info from access token    |
|`GET` |`/prm/:server_id`                        |Auto-generated PRM for a server|
|`POST`|`/api/servers`                           |Register an MCP server (admin) |
|`GET` |`/health`                                |Health check                   |

## Token Format

|Type          |Prefix |Lifetime  |Example          |
|--------------|-------|----------|-----------------|
|Access token  |`mat_` |1 hour    |`mat_dhcbqsgb...`|
|Refresh token |`mrt_` |30 days   |`mrt_ydqd0ug1...`|
|Auth code     |`code_`|10 minutes|`code_zkm6ukm...`|
|Server API key|`sak_` |Permanent |`sak_6rvstdl7...`|

All tokens are hashed (SHA-256) before storage. The plaintext is only returned once at creation.

## Project Structure

```
mcp-authkit-vercel/
├── api/
│   └── auth/
│       └── [...route].js     # Main Edge Function handler (~800 lines)
├── scripts/
│   └── init-db.js            # Database initialization script
├── schema.sql                # Turso database schema
├── vercel.json               # Vercel configuration
├── package.json
└── README.md
```

## Differences from Cloudflare Version

| Feature                  | Cloudflare Version    | Vercel Version       |
|--------------------------|-----------------------|----------------------|
| **Runtime**              | Cloudflare Workers    | Vercel Edge Functions|
| **Database**             | D1 (SQLite)           | Turso (LibSQL)       |
| **Database Access**      | `env.DB` binding      | `@libsql/client`     |
| **Config File**          | `wrangler.toml`       | `vercel.json`        |
| **Environment Variables**| Wrangler secrets      | Vercel env vars      |
| **CLI Tool**             | `wrangler`            | `vercel`             |
| **Edge Network**         | Cloudflare            | Vercel Edge          |
| **Cold Start**           | <50ms                 | <100ms               |
| **Free Tier**            | 100k requests/day     | 100GB bandwidth      |

**Core OAuth logic is identical** — the only difference is the database client and deployment platform.

## Local Development

```bash
# Install dependencies
npm install

# Set up environment variables
cp .env.example .env
# Edit .env with your Turso credentials

# Initialize database
npm run db:init

# Run local dev server
npm run dev
# → http://localhost:3000/api/auth
```

## Why Turso?

Turso provides:
- **Edge-hosted SQLite** - Your data lives close to your users globally
- **LibSQL compatibility** - Drop-in replacement for SQLite with edge optimizations
- **Generous free tier** - 9 GB storage, 1 billion rows, 1 billion row reads/month
- **Zero configuration** - No connection pooling, no replica lag, no sharding
- **Low latency** - Sub-10ms queries from edge locations worldwide

Perfect for an auth service that needs to be fast everywhere.

## Deployment Best Practices

1. **Custom Domain** - Set up a custom domain in Vercel for cleaner URLs
2. **Environment Separation** - Use different Turso databases for dev/staging/prod
3. **Monitoring** - Enable Vercel Analytics and Turso monitoring
4. **Rate Limiting** - Consider adding Vercel Rate Limiting for `/oauth/token`
5. **Backup** - Turso automatically handles backups on paid tiers

## ⚠️ Caveats

This is a reference implementation that powers a real product. It is not:

- A maintained open source library with SLAs
- A drop-in replacement for Auth0/Stytch/Clerk
- Battle-tested at massive scale (it works for our traffic)

Use it to learn from, fork it, steal the patterns. If you need production auth with support, use a dedicated auth provider.

## Troubleshooting

### Database connection errors

```bash
# Verify your Turso credentials
turso db show mcp-authkit

# Test connection
turso db shell mcp-authkit
# sqlite> .tables
```

### Deployment issues

```bash
# Check Vercel logs
vercel logs

# Redeploy with fresh environment
vercel --prod --force
```

### Token validation fails

Ensure your MCP server is calling `/api/auth/oauth/userinfo` with the Bearer token to validate it.

## License

[MIT](LICENSE)

## Credits

Built by [@jcameronjeff](https://x.com/devjefe) for [OpZero.sh](https://opzero.sh) — AI-native deployment infrastructure.

**Based on:** [MCP AuthKit](https://github.com/OpZero-sh/MCPAuthKit) (Cloudflare Workers version)

If this saves you the OAuth headache it saved us, consider giving [OpZero](https://opzero.sh) a look — it's the MCP deployment platform we built this for.

-----

## Related Projects

- [MCP AuthKit (Cloudflare)](https://github.com/OpZero-sh/MCPAuthKit) - Original Cloudflare Workers version
- [Turso](https://turso.tech) - Edge-hosted SQLite database
- [Model Context Protocol](https://modelcontextprotocol.io) - The spec this implements
