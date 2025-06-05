# OpenPhone Remote MCP Server

A production-ready remote Model Context Protocol (MCP) server that provides OpenPhone functionality through Cloudflare Workers. Send messages, manage contacts, and fetch call transcripts directly from Claude Desktop.

## 🌟 Features

- **📱 Messaging**: Send individual or bulk text messages via OpenPhone
- **👥 Contact Management**: Create and manage OpenPhone contacts
- **📞 Call Transcripts**: Fetch and analyze call transcripts (Business plan required)
- **🔐 Secure**: API key authentication with HTTPS encryption
- **⚡ Fast**: Powered by Cloudflare Workers for global edge deployment
- **🎨 Modern UI**: Beautiful homepage with setup instructions

## 🚀 Quick Setup

The easiest way to connect this MCP server to Claude Desktop:

### 1. Get Your OpenPhone API Key
1. Log into your [OpenPhone dashboard](https://app.openphone.com)
2. Go to Settings → Integrations → API
3. Generate an API key

### 2. Configure Claude Desktop
Update your Claude Desktop configuration file (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "openphone": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://mcp.openphonelabs.com/sse?apiKey=YOUR_OPENPHONE_API_KEY"
      ]
    }
  }
}
```

**Replace `YOUR_OPENPHONE_API_KEY`** with your actual API key.

### 3. Restart Claude Desktop
That's it! You can now ask Claude to help with OpenPhone tasks.

## 🛠️ Available Tools

| Tool | Description | Plan Required |
|------|-------------|---------------|
| **send-message** | Send text messages to any phone number | All plans |
| **bulk-messages** | Send the same message to multiple recipients | All plans |
| **create-contact** | Create contacts with email, phone, and company info | All plans |
| **fetch-call-transcripts** | Fetch and analyze call transcripts | Business plan |

## 💬 Usage Examples

Once configured, you can ask Claude to help with tasks like:

- *"Send a text to +1234567890 saying 'Meeting moved to 3pm'"*
- *"Create a contact for John Smith at Acme Corp with email john@acme.com and phone +1555123456"*
- *"Send a reminder message to my whole team about tomorrow's deadline"*
- *"Fetch the latest call transcripts from my main business line"*

## 🏗️ Development

### Prerequisites
- Node.js and npm
- Wrangler CLI (`npm install -g wrangler`)

### Local Setup
1. Clone this repository
2. Install dependencies:
   ```bash
   npm install
   ```

3. Start development server:
   ```bash
   npm run dev
   ```

4. Test with MCP Inspector:
   ```bash
   npx @modelcontextprotocol/inspector@latest
   ```
   - Set Transport Type to "SSE"
   - Use URL: `http://localhost:8787/sse?apiKey=YOUR_API_KEY`

### Local Testing with Claude Desktop
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

## 🏭 Production Deployment

### Deploy to Cloudflare Workers
```bash
wrangler deploy
```

Your server will be available at `https://your-worker.workers.dev/sse`

### Custom Domain (Optional)
Configure custom routes in `wrangler.jsonc`:
```json
{
  "routes": [
    "mcp.yourdomain.com/*"
  ]
}
```

## 🏛️ Architecture

### Technology Stack
- **Runtime**: Cloudflare Workers (V8 isolates)
- **Framework**: MCP SDK with Durable Objects
- **API**: OpenPhone REST API v1
- **Authentication**: API key via URL parameters
- **Deployment**: Cloudflare edge locations globally

### Security Model
- API keys transmitted via HTTPS only
- Per-request authentication validation
- No server-side API key storage
- Edge-based request processing

### File Structure
```
src/
├── index.ts                    # Worker entry point + homepage
├── openphone-api.ts           # OpenPhone API client
└── openphone-mcp-agent.ts     # MCP tools implementation
```

## 🔧 Configuration

### Environment Variables (Optional)
Set fallback configuration in Cloudflare Workers:
- `OPENPHONE_API_KEY`: Fallback API key (optional if using URL parameter)

### URL Parameters (Recommended)
- `?apiKey=xxx`: Your OpenPhone API key (highest priority)

## 📋 Requirements

### OpenPhone Account
- Active OpenPhone account
- API access enabled
- For call transcripts: Business plan subscription

### Claude Desktop
- Claude Desktop application
- MCP configuration access

## 🆘 Troubleshooting

### Common Issues

**"No tools available"**
- Check your API key is correct
- Verify the URL parameter format: `?apiKey=YOUR_KEY`
- Ensure your OpenPhone account has API access enabled

**"Error fetching call transcripts"**
- Call transcripts require OpenPhone Business plan
- Transcripts are only available for calls where transcription was enabled
- Check that the phone number exists in your workspace

**Connection timeout**
- Verify Claude Desktop configuration syntax
- Check internet connectivity
- Try restarting Claude Desktop

### Getting Help
1. Check the server homepage at your deployment URL for setup instructions
2. Verify API key permissions in OpenPhone dashboard
3. Test connection with MCP Inspector for debugging

## 🤝 Contributing

This project demonstrates building production-ready remote MCP servers with:
- Simple API key authentication
- Modern UI with setup instructions  
- Comprehensive error handling
- Edge deployment with Cloudflare Workers

Contributions welcome! Please feel free to submit issues and pull requests.

## 📄 License

MIT License - feel free to use this as a template for your own MCP servers.

---

**Built with ❤️ for the Claude Desktop community**
