## OpenPhone MCP – Beta handoff notes (@prd)

### What this is
- A remote Model Context Protocol (MCP) server that exposes selected OpenPhone capabilities to AI clients (Claude Desktop and ChatGPT connectors).
- Built as a Cloudflare Worker + Durable Object for stateless, low-latency operation at the edge.

### High-level architecture
- Runtime: Cloudflare Workers (V8 isolates)
- Entry: `src/index.ts` (routes, OAuth flow, landing page)
- MCP Agent: `src/openphone-mcp-agent.ts` (tool registration + handlers)
- OpenPhone API client: `src/openphone-api.ts` (thin REST client with validation and sanitized errors)
- Config: `wrangler.jsonc` (DO binding, routes)

### Endpoints (server)
- OAuth Discovery/Protected Resource: `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`
- OAuth Register/Authorize/Token: `/register`, `/authorize`, `/token` (OAuth 2.1 + PKCE)
- MCP transport: SSE endpoint (we’ve mounted via the Worker; in our public deployment we expose it as `/sse`)
- Default GET `/` serves a small developer landing page with setup instructions

### Tools (current set)
Registered in the MCP server (all require a valid OpenPhone API key):
- `send-message`: send a single SMS
- `bulk-messages`: send one message to multiple recipients
- `create-contact`: create a new contact
- `fetch-call-transcripts`: list calls and fetch transcripts (when available)
- `fetch-messages`: fetch recent messages by inbox and optional participant

Notes:
- We detect ChatGPT’s MCP UA and register a limited set, but the tool implementations are shared via helpers to avoid duplication.
- We intentionally removed generic “search”/“fetch” (deep-research style) and any AI planning middleware.

### Authentication & security
- OAuth 2.1 + PKCE: stateless tokens; keys are never placed in URLs
- `authGate` enforces auth for protected endpoints; API key can be provided via CF env, Authorization → stateless token, or `x-openphone-api-key`
- Security headers: CSP, X-Frame-Options, X-Content-Type-Options
- 30s request timeouts; errors are sanitized before returning
- No secrets committed in repo; `OPENPHONE_API_KEY` is read from CF env for testing/ops when present

### Client compatibility
- Claude Desktop: tested as a custom integration using our SSE URL
- ChatGPT (Connectors): implemented per OpenAI’s MCP; we support connector mode and gate the toolset accordingly

### Landing page (developer-centric)
- Modern, minimal UI with: theme toggle, sticky header, tabbed setup (Claude vs ChatGPT), tool accordions with copyable examples
- No config-file snippet for Claude (OAuth-only guidance)

### Design decisions
- Edge-first, stateless auth to avoid Worker cold starts impacting sessions
- Removed non-essential tools (generic search/fetch) and all AI middleware to reduce surface area
- Consolidated tool registrations into shared helpers to prevent drift between client modes
- Sanitized errors + conservative CSP by default; page script is inline but guarded by CSP

### What may change when integrating into the core codebase
- Route mounting and domains (we used a simple `/sse` and custom domain)
- Secrets management (swap CF env for your standard secrets store)
- OAuth issuer metadata & client registration pathing
- Logging/observability (we enabled CF observability; your stack may use different sinks/PII redaction)
- Rate limiting / abuse prevention (consider WAF rules or app-level quotas)
- SLOs, retries, and backoff policies for OpenPhone API calls

### Handoff pointers
- Start with: `src/index.ts` (routing + OAuth) and `src/openphone-mcp-agent.ts` (tools)
- Tool logic is straightforward and isolated; inputs are validated before calling OpenPhone
- The minimal OpenPhone client is at `src/openphone-api.ts`; it centralizes request/timeout/error behavior

### Repo link
- We’ll share the repository link in the ticket so engineering can browse full sources and diffs.

### Known constraints / open questions
- Transcripts require that transcription was enabled on calls and the appropriate OpenPhone plan
- We did not include generic research capabilities; if needed, reintroduce with internal retrieval patterns
- Consider adding structured JSON outputs alongside text for downstream UIs

### Suggested next steps for eng
- Wire up secrets in your environment; confirm OAuth client registration path
- Integrate with centralized logging/metrics; add request IDs and redaction rules
- Add comprehensive tests (tool schemas, happy-path + error-paths)
- Set rate limits + WAF and decide quotas per user/workspace
- Load test the Worker and DO to validate throughput + backpressure


