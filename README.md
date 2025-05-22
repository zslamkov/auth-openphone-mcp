# OpenPhone Remote MCP Server on Cloudflare

A remote Model Context Protocol (MCP) server that provides OpenPhone functionality through Cloudflare Workers.

## Current Status

✅ **Completed**:
- Basic remote MCP server infrastructure set up
- OpenPhone API client adapted for Cloudflare Workers (using native fetch)
- OpenPhone MCP Agent with three main tools:
  - `send-message`: Send individual text messages
  - `bulk-messages`: Send messages to multiple recipients
  - `create-contact`: Create contacts in OpenPhone
- **URL parameter API key support** - pass your API key directly in the Claude Desktop config
- Environment variable configuration for OpenPhone API key (fallback)
- Local development environment working
- Production deployment ready

## Tools Available

### OpenPhone Tools
- **send-message**: Send a text message from your OpenPhone number to a recipient
- **bulk-messages**: Send the same message to multiple recipients
- **create-contact**: Create new contacts with email, phone, and company information

*Note: If no OpenPhone API key is configured, you'll see a setup-instructions tool with configuration help.*

## 🚀 Quick Setup (Recommended)

The easiest way to use this MCP server is to pass your API key directly in your Claude Desktop configuration:

Update your Claude Desktop configuration (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "openphone": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://your-worker-url.workers.dev/sse?apiKey=YOUR_OPENPHONE_API_KEY"
      ]
    }
  }
}
```

**Replace `YOUR_OPENPHONE_API_KEY`** with your actual OpenPhone API key from your dashboard.

That's it! Restart Claude Desktop and you're ready to go.

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

3. Configure your OpenPhone API key (choose one method):

   **Option A: URL Parameter (matches production)**
   ```bash
   npm run dev
   # Then use: http://localhost:8787/sse?apiKey=your_api_key_here
   ```

   **Option B: Environment Variable**
   ```bash
   # Create .dev.vars file and add your actual API key
   echo "OPENPHONE_API_KEY=your_actual_openphone_api_key_here" > .dev.vars
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
   - Use URL: `http://localhost:8787/sse?apiKey=YOUR_API_KEY` (or `http://localhost:8787/sse` if using .dev.vars)
   - Click "Connect"

### Testing with Claude Desktop (Local)

For local testing, update your Claude Desktop configuration:

```json
{
  "mcpServers": {
    "openphone": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "http://localhost:8787/sse?apiKey=YOUR_OPENPHONE_API_KEY"
      ]
    }
  }
}
```

## Architecture

### Current Implementation
- **URL Parameter Based**: Pass your API key as `?apiKey=xxx` in the URL (recommended)
- **Environment Variable Fallback**: Uses OPENPHONE_API_KEY environment variable if no URL parameter
- **Cloudflare Workers**: Serverless execution environment
- **Durable Objects**: For stateful MCP operations
- **Native Fetch**: Uses Workers' built-in fetch instead of node-fetch

### File Structure
```
src/
├── index.ts                    # Main Worker entry point with URL parameter extraction
├── openphone-api.ts           # OpenPhone API client (adapted for Workers)
└── openphone-mcp-agent.ts     # MCP Agent implementation with tools
```

## Configuration Options

### Priority Order
1. **URL Parameter**: `?apiKey=YOUR_API_KEY` (highest priority)
2. **Environment Variable**: `OPENPHONE_API_KEY` (fallback)

### Environment Variables

Configure in Cloudflare Workers dashboard or `.dev.vars` for local development:
- `OPENPHONE_API_KEY`: Your OpenPhone API key (optional if using URL parameter)

## Deployment

### Option 1: URL Parameter Only (Recommended)
Just deploy without setting any environment variables:

```bash
wrangler deploy
```

Users pass their API key in the URL: `https://your-worker.workers.dev/sse?apiKey=xxx`

### Option 2: Environment Variable Fallback
Set a fallback API key in Cloudflare Workers:

```bash
wrangler secret put OPENPHONE_API_KEY
wrangler deploy
```

The deployed server will be available at `https://your-worker.workers.dev/sse`

## Usage Examples

### With Claude Desktop
Ask Claude to help with your OpenPhone tasks:

- *"Send a text to +1234567890 saying 'Meeting moved to 3pm'"*
- *"Create a contact for John Smith at Acme Corp with email john@acme.com"*
- *"Send the same message to multiple people about the project update"*

### With MCP Inspector
Connect to your server URL and explore the available tools interactively.

## Benefits of URL Parameter Approach

✅ **Simple setup** - Just add API key to Claude Desktop config  
✅ **No server configuration** - No need to set environment variables  
✅ **User-specific** - Each user uses their own API key  
✅ **Secure** - API key passed via HTTPS, not stored server-side  
✅ **Familiar pattern** - Same approach as Stripe and other MCP servers  

## Security

- Your API key is passed securely via HTTPS URL parameters
- API keys are validated before allowing access to tools
- No API keys stored server-side when using URL parameter approach
- Each request is validated independently

## Contributing

This implementation shows how to build a remote MCP server that accepts user credentials via URL parameters, similar to how other popular MCP servers work.
