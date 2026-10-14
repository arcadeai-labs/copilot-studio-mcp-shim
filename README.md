# Copilot Studio MCP shim for Arcade

A small, stateless proxy that lets **Microsoft Copilot Studio** connect to an **Arcade MCP gateway that has a user source** (for example, a gateway that signs users in with Microsoft Entra ID).

While Copilot is catching up on the MCP spec, this shim fills the gap. Host it in front of one gateway, point Copilot Studio at it, and your users sign in as themselves with the gateway's own identity provider. Once Copilot Studio sends what the spec asks for, delete the shim and point Copilot straight at Arcade.

> This is an [Arcade Labs](https://github.com/arcadeai-labs) project: shared as-is, without support or an SLA.

## The problem

The [MCP authorization spec](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) asks clients to tell the authorization server which MCP server a token is for, and to discover where to register. Copilot Studio's MCP connector doesn't do either yet:

1. **No `resource` parameter.** MCP clients must implement [RFC 8707 Resource Indicators](https://www.rfc-editor.org/rfc/rfc8707) and send `resource` on both the authorization and token requests. Copilot Studio sends it on neither. Arcade uses `resource` to tell which gateway a sign-in is for, and so which user source (identity provider) to use. Without it, the user signs in with Arcade's default identity, and a gateway that requires its own user source correctly rejects the token:

   ```text
   OAuth token's User Source does not match this gateway's configured User Source
   ```

2. **Advertised registration endpoint ignored.** With the "Dynamic" OAuth type, Copilot Studio doesn't use the `registration_endpoint` from the [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) authorization server metadata. It posts Dynamic Client Registration to `register` resolved against the server URL instead (`/mcp/register`, then `/mcp/<gateway>/register`), which isn't an endpoint on Arcade.

A related detail closes off the obvious workaround. When the authorization URL already has a query string, Copilot Studio appends its own parameters with a second `?` instead of `&`, so adding `?resource=...` to the URL by hand produces an invalid request.

Gateways **without** a user source connect from Copilot Studio today, because they don't depend on `resource`. The gap only shows up when a gateway signs users in with its own identity provider, which is exactly what enterprise deployments tend to want.

We've shared these findings with Microsoft, and we appreciate their partnership in getting the connector in line with the spec. This shim is a stopgap until then, not a replacement for the fix.

## What the shim does

The shim fronts exactly **one** gateway, set by configuration, and does four things:

| Request                                         | What the shim does                                                                                       |
| ----------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| OAuth discovery (`/.well-known/...`)            | Serves metadata that points Copilot at the shim's own OAuth endpoints, so the next three steps go through it. |
| Client registration (any of the paths Copilot tries) | Forwards to Arcade's real `/oauth2/register`, unchanged.                                                 |
| Authorize and token                             | Forwards to Arcade with `resource` set to the gateway, and adds `offline_access` so Copilot gets a refresh token. |
| MCP (`/mcp/<gateway>`)                          | Passes through to the gateway unchanged, streaming included.                                              |

Every other path is a 404. Because the gateway is fixed in configuration, the shim can only ever ask Arcade for tokens for that one gateway, whatever the client sends.

```text
Copilot Studio ──▶ shim (your domain) ──▶ Arcade OAuth  (resource pinned to your gateway)
                                      └─▶ Arcade gateway (MCP, passed through)
```

## Security

The shim is a TLS-terminating reverse proxy, so it sees OAuth codes and tokens in transit, the same way any load balancer or API gateway in front of a service does. Within that:

- **Run it yourself.** Arcade doesn't operate this shim. Host it in your own tenant or cloud subscription, on a domain you control, over HTTPS, so the tokens passing through it and its logs stay inside your environment. The shim refuses to start with an `http://` public URL, except on `localhost` for development. Run one shim per gateway.
- **It stores nothing.** No database, no cache, no session state. Every request is handled and forgotten.
- **It forwards only what Arcade needs.** Headers are passed on from an allowlist: the bearer token and MCP's own headers to the gateway, and only `content-type`, `accept`, and the user agent to Arcade's OAuth endpoints. Anything your own infrastructure adds in front of the shim, such as an API Management subscription key, App Service sign-in headers, or cookies, never reaches Arcade.
- **It never logs a credential.** Logged request headers come from a short allowlist (user agent, content type, MCP protocol version, and trace and correlation IDs), so bearer tokens, cookies, and any credential headers your infrastructure adds are left out. Codes, verifiers, client secrets, and access and refresh tokens are never written to logs either. Token requests log only *whether* each credential was present (`has_refresh_token: true`), which is what you need to debug a stale connection.
- **It doesn't log tool data by default.** MCP request and response bodies (tool arguments and results) are only logged if you set `SHIM_LOG_BODIES=true`.
- **It only reaches your gateway.** It pins `resource` to one gateway, so a client registered through it can only get tokens for that gateway, and Arcade still enforces the gateway's user source, access rules, and authorization exactly as it would without the shim. The shim holds no Arcade API key and has no privileges of its own.
- **It asks for refresh tokens.** The shim adds the `offline_access` scope to every sign-in, so Copilot gets a refresh token and connections don't go stale when the first access token expires. That means each connection holds a longer-lived credential than an access token alone. Revoking a user's authorization in Arcade cuts it off.
- **Registration is unchanged.** Dynamic Client Registration is forwarded as-is; it's open on Arcade too, as the MCP spec expects. Because registration is open, anyone can create a client and send your users a sign-in link on your shim's domain. Arcade's consent page names the client asking for access, and users should only approve clients they recognize. To close this off, set `SHIM_ALLOWED_REDIRECT_HOSTS` to Copilot Studio's callback host (`global.consent.azure-apim.net` for the public cloud): the shim then refuses (`400`) any registration or sign-in whose redirect URI points anywhere else, so a link on your domain can only land back in Copilot Studio. Confirm the host from the shim's own `register` log line, under `redirect_uris`, since sovereign clouds use a different one. This doesn't stop someone registering a client directly with Arcade; it only keeps your domain out of the link.
- **Anyone can reach it.** The shim has no credentials of its own and no rate limiting; it relays whatever it receives to Arcade, which does the authenticating. Arcade sees every request from the shim's egress address, so an abuser hitting your shim is rate-limited as you. Copilot Studio can't send a custom header, so the only control before OAuth is network: put the shim behind your API gateway or WAF with rate limits, and restrict ingress to Power Platform's egress addresses (the `PowerPlatformInfra` and `AzureConnectors` service tags on Azure).
- **Client secrets are dropped.** Copilot registers a public client, but Power Platform's refresh request sends an empty `client_secret` (or Basic auth) anyway, which Arcade would refuse for a public client. The shim removes it before forwarding.
- **Requests are bounded.** OAuth request bodies are capped at 64 KiB and MCP bodies at 10 MiB (`SHIM_MAX_BODY_BYTES`), refused with `413` before they're read into memory. Arcade's OAuth endpoints get 30 seconds to answer and the gateway 300 seconds to start answering, after which the shim returns `504`. A client that disconnects cancels the call to Arcade. The Node and Docker builds also close connections whose request takes more than 30 seconds to arrive; response streams aren't affected.

## Deploy

The shim is a web-standard `fetch` handler (`src/shim.ts`) with thin entry points for each runtime. Pick whichever your team already runs. It needs outbound HTTPS to `api.arcade.dev` and `cloud.arcade.dev`.

Keep it **always on**: Copilot Studio times out on cold starts, so avoid scale-to-zero settings.

### Docker (Azure Container Apps, App Service, ECS, Cloud Run, Render, Fly, Kubernetes, ...)

```bash
docker build -t copilot-studio-mcp-shim .
```

```bash
docker run -p 8080:8080 -e SHIM_PUBLIC_URL=https://mcp.example.com -e SHIM_GATEWAY=my-gateway copilot-studio-mcp-shim
```

The image listens on `PORT` (default `8080`) and has a health check at `/health`.

### Node.js (20 or later)

```bash
npm ci && npm run build && npm start
```

### Bun

```bash
bun install && bun run start:bun
```

### Vercel

Import the repo as a project, set the environment variables below, and deploy. `vercel.json` routes every path to one function (`api/index.js`) with a 300-second limit for streamed MCP responses.

### Cloudflare Workers

Set `SHIM_PUBLIC_URL` and `SHIM_GATEWAY` in `wrangler.toml` (or the dashboard), then:

```bash
npx wrangler deploy
```

## Configuration

| Variable                      | Required | Default                    | Description                                                                                                  |
| ----------------------------- | -------- | -------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `SHIM_PUBLIC_URL`             | yes      |                            | The URL the shim is served at, e.g. `https://mcp.example.com`. Must be `https://`; `http://` is only accepted for `localhost` and `127.0.0.1`. |
| `SHIM_GATEWAY`                | yes      |                            | The slug of the Arcade gateway to front (the last part of `https://api.arcade.dev/mcp/<slug>`).               |
| `ARCADE_API_URL`              | no       | `https://api.arcade.dev`   | Arcade's MCP API. Change it for a self-hosted Arcade.                                                         |
| `ARCADE_AUTH_URL`             | no       | `https://cloud.arcade.dev` | Arcade's OAuth server. Change it for a self-hosted Arcade.                                                    |
| `SHIM_ALLOWED_REDIRECT_HOSTS` | no       | any                        | Comma-separated hostnames a sign-in may redirect back to, e.g. `global.consent.azure-apim.net` or `*.consent.azure-apim.net` (a leading `*.` matches subdomains). When set, registration and authorize requests with any other redirect host get `400`, and authorize requires `redirect_uri`. Read Copilot Studio's host from the `redirect_uris` in the shim's `register` log line. |
| `SHIM_LOG_BODIES`             | no       | `false`                    | Also log MCP request and response bodies to the OTLP sink. These can hold user data and, in tool results, Arcade authorization links. |
| `SHIM_MAX_BODY_BYTES`         | no       | `10485760` (10 MiB)        | Largest MCP request body accepted. OAuth bodies are always capped at 64 KiB.                                  |
| `SHIM_OAUTH_TIMEOUT_MS`       | no       | `30000`                    | How long Arcade's OAuth endpoints get to answer before the shim returns `504`.                                |
| `SHIM_MCP_TIMEOUT_MS`         | no       | `300000`                   | How long the gateway gets to start answering an MCP request. Event streams, once started, aren't cut off.     |
| `PORT`                        | no       | `8080`                     | Listen port (Docker, Node, Bun).                                                                              |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | no       |                            | Send each request as an OTLP/HTTP JSON log record to this collector, e.g. `http://otel-collector:4318`.       |
| `OTEL_EXPORTER_OTLP_HEADERS`  | no       |                            | Headers for the OTLP endpoint, as `key=value,key2=value2`. This usually holds a collector API key, so store it as a secret (`wrangler secret put`, or your platform's secret store), not a plain variable. |
| `OTEL_SERVICE_NAME`           | no       | `copilot-studio-mcp-shim`  | `service.name` on exported logs.                                                                              |
| `SHIM_VERSION`                | no       | detected                   | Build identifier on every log line. Detected from Vercel, Render, and common CI variables when not set.       |

Every request (except `/health`) is logged to stdout as one JSON line with `event: "mcp_shim_request"`, the route, status, timing, the MCP method and tool name, and a few claims from the bearer token (`iss`, `aud`, `sub`, `client_id`, `scope`, `exp`). The shim reads those claims without verifying the token, so treat them as what the caller presented, not as proof of identity; Arcade verifies the token, and the logged `status` says whether it accepted it.

## Connect Copilot Studio

1. In Copilot Studio, open your agent (use **Agent (Standard)**) and go to **Tools → Add a tool → New tool → Model Context Protocol**.
2. Fill in:

   | Field          | Value                                                                    |
   | -------------- | ------------------------------------------------------------------------ |
   | Server URL     | `https://<your shim>/mcp/<gateway>/` (keep the trailing `/`)             |
   | Authentication | **OAuth 2.0**, type **Dynamic discovery**                                |

3. **Create**, then **Create new connection**. Sign in with your identity provider, then approve Arcade's consent page, which should name your gateway.
4. Turn on the tools the agent should use and **Save**.
5. Make sure the tool uses **each end user's credentials**, not the maker's connection, so every user acts as themselves.

Use **Dynamic discovery** rather than **Dynamic**. Both connect through the shim, but a "Dynamic" connector is created without a refresh URL, so its connection goes stale when the first access token expires.

## Check it's working

```bash
curl -s https://<your shim>/health
```

That returns `{"status":"healthy"}`. Then:

```bash
curl -s https://<your shim>/.well-known/oauth-protected-resource/mcp/<gateway>
```

That should list the shim (not Arcade) under `authorization_servers`. In the logs, a healthy connection shows `register`, `authorize`, and `token` routes, then `mcp` requests with `initialize` and `tools/list`. If a connection goes stale, look at the `token` lines: `has_refresh_token` on the response says whether Arcade issued one, and a `grant_type: refresh_token` request shows Copilot refreshing.

## When Copilot Studio is fixed

Once Copilot Studio sends `resource` and uses the advertised registration endpoint, remove the tool, add it again with the server URL `https://api.arcade.dev/mcp/<gateway>/` (Dynamic discovery), and shut the shim down. Nothing on the Arcade side needs to change.

## Development

```bash
npm ci
npm test            # needs Bun (bun test)
npm run check       # Biome and TypeScript
npm run build       # compile to dist/ for Node and Vercel
npm run dev         # Bun, with reload
```
