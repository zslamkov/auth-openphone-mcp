import { OpenPhoneMCPAgent } from "./openphone-mcp-agent.js";

export { OpenPhoneMCPAgent };

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext) {
		const url = new URL(request.url);

		// Extract headers for secure API key transmission
		const headers = Object.fromEntries(request.headers.entries());
		
		// Pass headers and URL params to the agent
		const searchParams = Object.fromEntries(url.searchParams.entries());
		ctx.props = { ...headers, ...searchParams };

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
			headers: { 
				'Content-Type': 'text/html',
				'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' fonts.googleapis.com; font-src fonts.gstatic.com",
				'X-Frame-Options': 'DENY',
				'X-Content-Type-Options': 'nosniff',
				'Referrer-Policy': 'strict-origin-when-cross-origin'
			}
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
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body { 
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #1a202c;
        }
        
        .container {
            max-width: 1000px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .hero { 
            text-align: center; 
            margin-bottom: 4rem;
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(20px);
            padding: 4rem 3rem;
            border-radius: 24px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            border: 1px solid rgba(255,255,255,0.2);
        }
        
        .hero h1 {
            font-size: 3.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 1rem;
        }
        
        .hero p {
            font-size: 1.3rem;
            color: #64748b;
            font-weight: 400;
        }
        
        .card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(20px);
            padding: 2.5rem;
            border-radius: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.08);
            margin: 2rem 0;
            border: 1px solid rgba(255,255,255,0.2);
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }
        
        .card:hover {
            transform: translateY(-4px);
            box-shadow: 0 20px 40px rgba(0,0,0,0.12);
        }
        
        .card h2 {
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 1.5rem;
            color: #1e293b;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        
        .icon {
            font-size: 1.8rem;
        }
        
        .code { 
            background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
            color: #e2e8f0;
            padding: 1.5rem;
            border-radius: 12px;
            font-family: 'SF Mono', 'Monaco', 'Inconsolata', 'Roboto Mono', monospace;
            overflow-x: auto;
            font-size: 0.9rem;
            line-height: 1.6;
            border: 1px solid #475569;
            position: relative;
        }
        
        .code pre {
            margin: 0;
            padding: 0;
            font-family: inherit;
            white-space: pre;
            tab-size: 2;
        }
        
        .code::before {
            content: 'config.json';
            position: absolute;
            top: -10px;
            left: 1rem;
            background: #475569;
            color: #cbd5e1;
            padding: 0.25rem 0.75rem;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 500;
        }
        
        .copy-button {
            position: absolute;
            top: 1rem;
            right: 1rem;
            background: rgba(148, 163, 184, 0.1);
            border: 1px solid rgba(148, 163, 184, 0.2);
            color: #cbd5e1;
            padding: 0.5rem;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.8rem;
            font-weight: 500;
        }
        
        .copy-button:hover {
            background: rgba(148, 163, 184, 0.2);
            border-color: rgba(148, 163, 184, 0.4);
            transform: translateY(-1px);
        }
        
        .copy-button.copied {
            background: rgba(34, 197, 94, 0.2);
            border-color: rgba(34, 197, 94, 0.4);
            color: #22c55e;
        }
        
        .copy-icon {
            width: 16px;
            height: 16px;
        }
        
        .highlight {
            background: linear-gradient(135deg, #fef3cd 0%, #fed7aa 100%);
            border: 1px solid #f59e0b;
            color: #92400e;
            padding: 1.25rem;
            border-radius: 12px;
            margin: 1.5rem 0;
            position: relative;
            overflow: hidden;
        }
        
        .highlight::before {
            content: '';
            position: absolute;
            left: 0;
            top: 0;
            height: 100%;
            width: 4px;
            background: #f59e0b;
        }
        
        .tools-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 1rem;
            margin-top: 1.5rem;
        }
        
        .tool-item {
            background: rgba(248, 250, 252, 0.8);
            padding: 1.25rem;
            border-radius: 12px;
            border: 1px solid #e2e8f0;
            transition: all 0.2s ease;
        }
        
        .tool-item:hover {
            background: rgba(255, 255, 255, 0.9);
            transform: translateY(-2px);
        }
        
        .tool-name {
            font-weight: 600;
            color: #1e293b;
            margin-bottom: 0.5rem;
            font-size: 0.95rem;
        }
        
        .tool-desc {
            font-size: 0.85rem;
            color: #64748b;
            line-height: 1.5;
        }
        
        .badge {
            display: inline-block;
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            margin-left: 0.5rem;
        }
        
        .footer {
            text-align: center;
            margin-top: 3rem;
            padding: 2rem;
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(20px);
            border-radius: 16px;
            border: 1px solid rgba(255,255,255,0.2);
        }
        
        .footer p {
            color: rgba(255, 255, 255, 0.9);
            font-weight: 300;
        }
        
        @media (max-width: 768px) {
            .hero h1 {
                font-size: 2.5rem;
            }
            
            .container {
                padding: 1rem;
            }
            
            .hero {
                padding: 2.5rem 2rem;
            }
            
            .card {
                padding: 2rem;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="hero">
            <h1>📞 OpenPhone MCP</h1>
            <p>AI-powered messaging and contact management for the modern workspace</p>
        </div>
        
        <div class="card">
            <h2><span class="icon">🚀</span>Quick Setup</h2>
            <p><strong>Add this to your Claude Desktop configuration:</strong></p>
            
            <div class="code">
                <button class="copy-button" onclick="copyConfig(this)">
                    <svg class="copy-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                    </svg>
                    <span class="copy-text">Copy</span>
                </button>
<pre>{
  "mcpServers": {
    "openphone": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://mcp.openphonelabs.com/sse"
      ]
    }
  }
}</pre>
            </div>
            
            <div class="highlight">
                <strong>🔐 Set your API key as environment variable:</strong><br>
                <code>OPENPHONE_API_KEY=your_actual_api_key</code><br>
                Or use the X-OpenPhone-API-Key header for secure transmission.
            </div>
        </div>
        
        <div class="card">
            <h2><span class="icon">🛠️</span>Available Tools<span class="badge">4 Tools</span></h2>
            <div class="tools-grid">
                <div class="tool-item">
                    <div class="tool-name">💬 send-message</div>
                    <div class="tool-desc">Send text messages to any phone number instantly</div>
                </div>
                <div class="tool-item">
                    <div class="tool-name">📢 bulk-messages</div>
                    <div class="tool-desc">Send the same message to multiple recipients at once</div>
                </div>
                <div class="tool-item">
                    <div class="tool-name">👥 create-contact</div>
                    <div class="tool-desc">Create and manage contacts in your OpenPhone workspace</div>
                </div>
                <div class="tool-item">
                    <div class="tool-name">📞 fetch-call-transcripts</div>
                    <div class="tool-desc">Fetch and analyze call transcripts (Business plan required)</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2><span class="icon">🔒</span>Enterprise Security</h2>
            <p>Your API key is transmitted securely through encrypted HTTPS connections. The server validates your credentials before allowing access to any tools, ensuring your OpenPhone data remains protected.</p>
        </div>
        
        <div class="footer">
            <p>Powered by Cloudflare Workers • Built for Claude Desktop</p>
        </div>
    </div>

    <script>
        function copyConfig(button) {
            const configText = JSON.stringify({
                mcpServers: {
                    openphone: {
                        command: "npx",
                        args: [
                            "mcp-remote",
                            "https://mcp.openphonelabs.com/sse"
                        ]
                    }
                }
            }, null, 2);
            
            navigator.clipboard.writeText(configText).then(() => {
                const originalText = button.querySelector('.copy-text').textContent;
                button.classList.add('copied');
                button.querySelector('.copy-text').textContent = 'Copied!';
                
                setTimeout(() => {
                    button.classList.remove('copied');
                    button.querySelector('.copy-text').textContent = originalText;
                }, 2000);
            }).catch(err => {
                console.error('Failed to copy: ', err);
                // Fallback for older browsers
                const textArea = document.createElement('textarea');
                textArea.value = configText;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                
                const originalText = button.querySelector('.copy-text').textContent;
                button.classList.add('copied');
                button.querySelector('.copy-text').textContent = 'Copied!';
                
                setTimeout(() => {
                    button.classList.remove('copied');
                    button.querySelector('.copy-text').textContent = originalText;
                }, 2000);
            });
        }
    </script>
</body>
</html>
  `;
}
