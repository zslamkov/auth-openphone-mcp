# OpenPhone Remote MCP Server

A production-ready remote Model Context Protocol (MCP) server that provides OpenPhone functionality through Cloudflare Workers. Send messages, manage contacts, and fetch call transcripts directly from Claude Desktop.

## 🌟 Features

- **📱 Messaging**: Send individual or bulk text messages via OpenPhone
- **👥 Contact Management**: Create and manage OpenPhone contacts
- **📞 Call Transcripts**: Fetch and analyze call transcripts (Business plan required)
- **🔐 Enterprise Security**: Multiple authentication methods, input validation, security headers
- **⚡ Fast**: Powered by Cloudflare Workers for global edge deployment
- **🎨 Modern UI**: Beautiful homepage with setup instructions

## 🔒 Security Features

- **Multiple Authentication Methods**: Headers, environment variables, or URL parameters
- **Input Validation**: Phone number format validation, message length limits
- **Security Headers**: CSP, X-Frame-Options, X-Content-Type-Options
- **Request Timeouts**: 30-second timeout protection
- **Error Sanitization**: No sensitive information disclosure

## 🚀 Quick Setup

The easiest way to connect this MCP server to Claude Desktop:

### 1. Get Your OpenPhone API Key
1. Log into your [OpenPhone dashboard](https://app.openphone.com)
2. Go to Settings → Integrations → API
3. Generate an API key

### 2. Configure Claude Desktop

**⚠️ Security Notice:** The configuration below includes API keys in URLs, which are visible in logs and browser history. This is a limitation of the `mcp-remote` tool.

**Claude Desktop Configuration:**
Update your Claude Desktop configuration file (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "openphone": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://mcp.openphonelabs.com/sse?key=your_actual_api_key"
      ]
    }
  }
}
```

**Alternative parameter names (all work the same):**
- `?key=your_api_key` (recommended - shorter)
- `?apiKey=your_api_key` (verbose)
- `?token=your_api_key` (alternative)

**🔒 For Production/Enterprise Use:**
To eliminate the URL parameter security risk:
1. Deploy your own instance of this server to Cloudflare Workers
2. Set `OPENPHONE_API_KEY` as a Cloudflare Workers environment variable
3. Use the URL without parameters: `https://your-worker.workers.dev/sse`
4. Or use the direct MCP connection instead of `mcp-remote`

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
- **Multiple Auth Methods**: Headers (preferred), environment variables, URL parameters (deprecated)
- **Input Validation**: Phone number format, message length, API key format validation
- **Security Headers**: Content Security Policy, X-Frame-Options, X-Content-Type-Options
- **Error Sanitization**: Generic error messages prevent information disclosure
- **Request Timeouts**: 30-second timeout prevents hanging requests
- **HTTPS Only**: All API communication encrypted
- **No Server Storage**: API keys never stored server-side

### File Structure
```
src/
├── index.ts                    # Worker entry point + homepage
├── openphone-api.ts           # OpenPhone API client
└── openphone-mcp-agent.ts     # MCP tools implementation
```

## 🔧 Configuration

### Authentication Priority Order
1. **Authorization Header**: `Authorization: Bearer YOUR_API_KEY`
2. **Custom Header**: `X-OpenPhone-API-Key: YOUR_API_KEY`
3. **Environment Variable**: `OPENPHONE_API_KEY=YOUR_API_KEY`
4. **URL Parameter** (deprecated): `?apiKey=YOUR_API_KEY`

### Environment Variables
Set in Cloudflare Workers or local environment:
- `OPENPHONE_API_KEY`: Your OpenPhone API key

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
- Check your API key is correct and properly formatted
- Verify authentication method (environment variable, header, or URL parameter)
- Ensure your OpenPhone account has API access enabled
- Check API key length (should be 16-128 characters) and contains only valid characters

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
