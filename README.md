# OpenPhone Remote MCP Server

A production-ready remote Model Context Protocol (MCP) server that provides OpenPhone functionality through Cloudflare Workers. Send messages, manage contacts, and fetch call transcripts directly from Claude Desktop.

## 🌟 Features

- **📱 Messaging**: Send individual or bulk text messages via OpenPhone
- **👥 Contact Management**: Create and manage OpenPhone contacts
- **📞 Call Transcripts**: Fetch and analyze call transcripts (Business plan required)
- **🔐 OAuth 2.1 + PKCE**: Industry-standard authentication with enhanced security
- **⚡ Fast**: Powered by Cloudflare Workers for global edge deployment
- **🎨 Modern UI**: Beautiful homepage with setup instructions

## 🔒 Security Features

- **OAuth 2.1 + PKCE**: Industry-standard authentication prevents API key exposure
- **Stateless Tokens**: JWT-style tokens with embedded signatures survive worker restarts
- **No URLs Parameters**: API keys never exposed in logs, browser history, or referrer headers
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

**Method 1: Direct Integration (Recommended)**
1. Open Claude Desktop
2. Go to **Settings > Integrations**
3. Click **"Add custom integration"**
4. Enter:
   - **Name**: OpenPhone
   - **URL**: `https://mcp.openphonelabs.com/sse`
5. Click **"Connect"**
6. When prompted, enter your OpenPhone API key securely

**Method 2: Configuration File**
Update your Claude Desktop configuration file (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "openphone": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://mcp.openphonelabs.com/sse"
      ]
    }
  }
}
```

**🔐 Enhanced Security:**
- OAuth 2.1 + PKCE authentication ensures your API keys are never exposed in URLs
- Claude Desktop will securely prompt for your API key during the first connection
- All authentication tokens are stateless and survive Cloudflare Workers restarts

### 3. Start Using OpenPhone Tools
That's it! You should now see OpenPhone tools available in Claude Desktop. You can ask Claude to help with OpenPhone tasks like sending messages or managing contacts.

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
   - Use URL: `http://localhost:8787/sse`
   - When prompted, enter your OpenPhone API key

### Local Testing with Claude Desktop
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
- **Authentication**: OAuth 2.1 + PKCE with stateless tokens
- **Deployment**: Cloudflare edge locations globally

### Security Model
- **OAuth 2.1 + PKCE**: Industry-standard authentication with Proof Key for Code Exchange
- **Stateless Tokens**: JWT-style tokens with embedded signatures survive worker restarts
- **No URL Parameters**: API keys never exposed in URLs, logs, or browser history
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

### OAuth 2.1 + PKCE Authentication
This server implements industry-standard OAuth 2.1 with PKCE (Proof Key for Code Exchange):

1. **Authorization Endpoint**: `/authorize` - Handles consent and API key validation
2. **Token Endpoint**: `/token` - Exchanges authorization codes for access tokens  
3. **Discovery Endpoint**: `/.well-known/oauth-authorization-server` - OAuth metadata
4. **Registration Endpoint**: `/register` - Dynamic client registration

### Authentication Flow
1. Claude Desktop registers as OAuth client
2. User redirected to consent page for API key entry
3. Server validates API key against OpenPhone API
4. Authorization code generated with embedded API key
5. Code exchanged for stateless access token
6. Token validates requests to protected MCP endpoints

### Environment Variables (Optional)
Set in Cloudflare Workers for additional security:
- `OPENPHONE_API_KEY`: Pre-configured API key (bypasses OAuth for testing)

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
- Ensure you completed the OAuth authentication flow when prompted
- Verify your OpenPhone account has API access enabled
- Check API key length (should be 16-128 characters) and contains only valid characters
- Try restarting Claude Desktop to refresh the OAuth connection

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
- OAuth 2.1 + PKCE authentication
- Stateless token architecture for Cloudflare Workers
- Modern UI with secure consent flow
- Comprehensive error handling
- Edge deployment with global scalability

Contributions welcome! Please feel free to submit issues and pull requests.

## 📄 License

MIT License - feel free to use this as a template for your own MCP servers.

---

**Built with ❤️ for the Claude Desktop community**
