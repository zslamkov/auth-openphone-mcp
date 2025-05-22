import { OpenPhoneMCPAgent } from "./openphone-mcp-agent.js";

export { OpenPhoneMCPAgent };

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext) {
		const url = new URL(request.url);

		// Extract API key from URL parameter
		const apiKey = url.searchParams.get('apiKey');

		// Pass API key through execution context
		if (apiKey) {
			ctx.props = { apiKey };
		}

		// Handle MCP SSE endpoint
		if (url.pathname === "/sse" || url.pathname === "/sse/message") {
			return OpenPhoneMCPAgent.serveSSE("/sse").fetch(request, env, ctx);
		}

		// Handle MCP endpoint
		if (url.pathname === "/mcp") {
			return OpenPhoneMCPAgent.serve("/mcp").fetch(request, env, ctx);
		}

		// Default homepage with instructions
		return new Response(getHomepageHTML(), {
			headers: { 'Content-Type': 'text/html' }
		});
	},
};

function getHomepageHTML(): string {
	return `
<!DOCTYPE html>
<html>
<head>
    <title>OpenPhone MCP Server</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 800px; 
            margin: 0 auto; 
            padding: 2rem; 
            line-height: 1.6; 
            background: #f8fafc;
        }
        .hero { 
            text-align: center; 
            margin-bottom: 3rem; 
            background: white;
            padding: 3rem;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.05);
        }
        .card {
            background: white;
            padding: 2rem;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.05);
            margin: 2rem 0;
        }
        .code { 
            background: #1a202c;
            color: #e2e8f0;
            padding: 1rem;
            border-radius: 6px;
            font-family: 'Monaco', 'Menlo', monospace;
            overflow-x: auto;
            font-size: 0.9rem;
        }
        .highlight {
            background: #fef5e7;
            border: 1px solid #f6ad55;
            color: #c05621;
            padding: 1rem;
            border-radius: 6px;
            margin: 1rem 0;
        }
    </style>
</head>
<body>
    <div class="hero">
        <h1>📞 OpenPhone MCP Server</h1>
        <p>AI-powered messaging and contact management</p>
    </div>
    
    <div class="card">
        <h2>🚀 Quick Setup</h2>
        <p><strong>Just add this to your Claude Desktop config:</strong></p>
        
        <div class="code">
{
  "mcpServers": {
    "openphone": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://your-openphone-server.workers.dev/sse?apiKey=YOUR_OPENPHONE_API_KEY"
      ]
    }
  }
}
        </div>
        
        <div class="highlight">
            <strong>📝 Replace YOUR_OPENPHONE_API_KEY</strong> with your actual OpenPhone API key from your dashboard.
        </div>
    </div>
    
    <div class="card">
        <h2>🔧 Available Tools</h2>
        <ul style="padding-left: 1.5rem;">
            <li><strong>send-message</strong> - Send text messages to any phone number</li>
            <li><strong>bulk-messages</strong> - Send the same message to multiple recipients</li>
            <li><strong>create-contact</strong> - Create and manage contacts in OpenPhone</li>
        </ul>
    </div>

    <div class="card">
        <h2>🔒 Security</h2>
        <p>Your API key is passed securely through the URL parameter. The server validates your key before allowing access to any tools.</p>
    </div>
</body>
</html>
  `;
}
