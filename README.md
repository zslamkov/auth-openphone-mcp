# OpenPhone Remote MCP Server on Cloudflare

A remote Model Context Protocol (MCP) server that provides OpenPhone functionality through Cloudflare Workers.

## Current Status

✅ **Completed**:
- Basic remote MCP server infrastructure set up
- OpenPhone API client adapted for Cloudflare Workers (using native fetch)
- OpenPhone MCP Agent with three main tools:
  - `setup-api-key`: Configure OpenPhone API key
  - `send-message`: Send individual text messages
  - `bulk-messages`: Send messages to multiple recipients
  - `create-contact`: Create contacts in OpenPhone
- Local development environment working

🎯 **Next Steps**:
- Environment variable configuration for OpenPhone API key
- Authentication system with GitHub OAuth
- User-specific API key storage using KV
- Production deployment

## Tools Available

### Setup Tool
- **setup-api-key**: Currently shows placeholder message - will be enhanced to save API keys per user

### OpenPhone Tools
- **send-message**: Send a text message from your OpenPhone number to a recipient
- **bulk-messages**: Send the same message to multiple recipients
- **create-contact**: Create new contacts with email, phone, and company information

## Local Development

### Prerequisites
- Node.js and npm
- Wrangler CLI

### Setup
1. Clone this repository
2. Install dependencies:
   ```bash
   npm install
   ```

3. Configure your OpenPhone API key:
   ```bash
   # Edit .dev.vars file and replace with your actual API key
   OPENPHONE_API_KEY=your_actual_openphone_api_key_here
   ```

4. Start the development server:
   ```bash
   npm run dev
   ```

5. Test with MCP Inspector:
   ```bash
   npx @modelcontextprotocol/inspector@latest
   ```
   - Set Transport Type to "SSE"
   - Use URL: `http://localhost:8787/sse`
   - Click "Connect"
   
   **Without API Key**: You'll see only the `setup-api-key` tool with instructions
   **With API Key**: You'll see all OpenPhone tools (send-message, bulk-messages, create-contact)

### Testing with Claude Desktop

Update your Claude Desktop configuration (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "openphone": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "http://localhost:8787/sse"
      ]
    }
  }
}
```

## Architecture

### Current Implementation
- **Authless**: No authentication required currently
- **Cloudflare Workers**: Serverless execution environment
- **Durable Objects**: For stateful operations (configured but not used yet)
- **Native Fetch**: Uses Workers' built-in fetch instead of node-fetch

### File Structure
```
src/
├── index.ts                    # Main Worker entry point
├── openphone-api.ts           # OpenPhone API client (adapted for Workers)
└── openphone-mcp-agent.ts     # MCP Agent implementation with tools
```

## Adding Authentication (Planned)

The next major step is to add GitHub OAuth authentication:

1. Switch to the GitHub OAuth template structure
2. Add KV namespace for storing user API keys
3. Implement per-user API key management
4. Add proper environment variable handling

## Environment Variables

Will be configured for:
- `OPENPHONE_API_KEY`: For server-wide API key (development)
- `GITHUB_CLIENT_ID`: For OAuth (when authentication added)
- `GITHUB_CLIENT_SECRET`: For OAuth (when authentication added)

## Deployment

Deploy to Cloudflare:
```bash
wrangler deploy
```

The deployed server will be available at `https://your-worker.workers.dev/sse`

## Contributing

This is based on the implementation plan in `implementation_plan.md` which shows the step-by-step conversion from a local stdio MCP server to a remote Cloudflare-hosted server with authentication.
