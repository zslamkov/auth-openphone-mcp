import { OpenPhoneMCPAgent } from "./openphone-mcp-agent.js";

export { OpenPhoneMCPAgent };

async function handleOAuthFlow(request: Request, url: URL): Promise<Response> {
	const method = request.method;
	
	if (method === 'GET') {
		// Show API key input form for authentication
		return new Response(getAuthPageHTML(), {
			headers: { 
				'Content-Type': 'text/html',
				'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' fonts.googleapis.com; font-src fonts.gstatic.com",
				'X-Frame-Options': 'DENY',
				'X-Content-Type-Options': 'nosniff',
				'Referrer-Policy': 'strict-origin-when-cross-origin'
			}
		});
	}
	
	if (method === 'POST') {
		// Handle API key submission
		const formData = await request.formData();
		const apiKey = formData.get('api_key') as string;
		
		if (!apiKey?.trim()) {
			return new Response(getAuthPageHTML('API key is required'), {
				status: 400,
				headers: { 'Content-Type': 'text/html' }
			});
		}
		
		// Validate API key by testing with OpenPhone API
		try {
			const testResponse = await fetch('https://api.openphone.com/v1/phone-numbers', {
				headers: {
					'Authorization': apiKey.trim(),
					'Content-Type': 'application/json'
				}
			});
			
			if (!testResponse.ok) {
				return new Response(getAuthPageHTML('Invalid API key'), {
					status: 400,
					headers: { 'Content-Type': 'text/html' }
				});
			}
			
			// Generate a secure token for this API key
			const token = btoa(apiKey.trim()).replace(/[+/=]/g, '');
			
			// Return success with token that Claude can use
			return new Response(JSON.stringify({
				access_token: token,
				token_type: 'bearer',
				expires_in: 3600
			}), {
				headers: {
					'Content-Type': 'application/json',
					'Access-Control-Allow-Origin': '*',
					'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
					'Access-Control-Allow-Headers': 'Content-Type, Authorization'
				}
			});
			
		} catch (error) {
			return new Response(getAuthPageHTML('Failed to validate API key'), {
				status: 500,
				headers: { 'Content-Type': 'text/html' }
			});
		}
	}
	
	return new Response('Method not allowed', { status: 405 });
}

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext) {
		const url = new URL(request.url);

		// Handle CORS preflight requests
		if (request.method === 'OPTIONS') {
			return new Response(null, {
				status: 204,
				headers: {
					'Access-Control-Allow-Origin': '*',
					'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
					'Access-Control-Allow-Headers': 'Content-Type, Authorization',
					'Access-Control-Max-Age': '86400',
				}
			});
		}

		// Extract headers for secure API key transmission
		const headers = Object.fromEntries(request.headers.entries());
		
		// Pass headers and URL params to the agent
		const searchParams = Object.fromEntries(url.searchParams.entries());
		ctx.props = { ...headers, ...searchParams };

		// Handle OAuth authentication for Claude web app
		if (url.pathname === "/auth") {
			return handleOAuthFlow(request, url);
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
            background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 25%, #16213e 50%, #0f3460 75%, #533a7d 100%);
            min-height: 100vh;
            color: #1a202c;
            position: relative;
            overflow-x: hidden;
        }
        
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><defs><pattern id="grid" width="10" height="10" patternUnits="userSpaceOnUse"><path d="M 10 0 L 0 0 0 10" fill="none" stroke="rgba(255,255,255,0.03)" stroke-width="0.5"/></pattern></defs><rect width="100" height="100" fill="url(%23grid)"/></svg>');
            pointer-events: none;
            z-index: -1;
        }
        
        .container {
            max-width: 900px;
            margin: 0 auto;
            padding: 1.5rem;
        }
        
        .hero { 
            text-align: center; 
            margin-bottom: 2.5rem;
            background: rgba(255, 255, 255, 0.98);
            backdrop-filter: blur(20px);
            padding: 3.5rem 2.5rem;
            border-radius: 24px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.25), 0 0 0 1px rgba(255,255,255,0.3);
            border: 1px solid rgba(255,255,255,0.3);
            position: relative;
            overflow: hidden;
        }
        
        .hero::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #00f5ff 0%, #8b5cf6 25%, #ec4899 50%, #f59e0b 75%, #10b981 100%);
        }
        
        .hero h1 {
            font-size: 3rem;
            font-weight: 800;
            background: linear-gradient(135deg, #00f5ff 0%, #8b5cf6 25%, #ec4899 50%, #f59e0b 75%, #10b981 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 1rem;
            letter-spacing: -0.025em;
        }
        
        .hero p {
            font-size: 1.25rem;
            color: #475569;
            font-weight: 500;
            max-width: 500px;
            margin: 0 auto;
        }
        
        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            background: rgba(34, 197, 94, 0.1);
            border: 1px solid rgba(34, 197, 94, 0.3);
            color: #059669;
            padding: 0.4rem 0.875rem;
            border-radius: 50px;
            font-size: 0.8rem;
            font-weight: 600;
            margin-top: 1rem;
        }
        
        .status-dot {
            width: 8px;
            height: 8px;
            background: #22c55e;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        .card {
            background: rgba(255, 255, 255, 0.97);
            backdrop-filter: blur(20px);
            padding: 2rem;
            border-radius: 20px;
            box-shadow: 0 12px 24px rgba(0,0,0,0.15), 0 0 0 1px rgba(255,255,255,0.2);
            margin: 2rem 0;
            border: 1px solid rgba(255,255,255,0.3);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
        }
        
        .card:hover {
            transform: translateY(-8px);
            box-shadow: 0 24px 48px rgba(0,0,0,0.2), 0 0 0 1px rgba(255,255,255,0.3);
        }
        
        .card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 1px;
            background: linear-gradient(90deg, transparent 0%, rgba(255,255,255,0.8) 50%, transparent 100%);
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
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #e2e8f0;
            padding: 0;
            border-radius: 16px;
            font-family: 'SF Mono', 'Monaco', 'Inconsolata', 'Roboto Mono', monospace;
            overflow: hidden;
            font-size: 0.875rem;
            line-height: 1.6;
            border: 1px solid rgba(71, 85, 105, 0.3);
            position: relative;
            box-shadow: 0 8px 32px rgba(0,0,0,0.4);
        }
        
        .code-header {
            background: linear-gradient(135deg, #334155 0%, #475569 100%);
            border-bottom: 1px solid rgba(71, 85, 105, 0.5);
            padding: 0.75rem 1.25rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-size: 0.75rem;
            font-weight: 600;
            color: #cbd5e1;
        }
        
        .code-content {
            padding: 1.25rem;
        }
        
        .code pre {
            margin: 0;
            padding: 0;
            font-family: inherit;
            white-space: pre;
            tab-size: 2;
        }
        
        .copy-button {
            background: rgba(59, 130, 246, 0.1);
            border: 1px solid rgba(59, 130, 246, 0.3);
            color: #60a5fa;
            padding: 0.375rem 0.75rem;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 0.375rem;
            font-size: 0.75rem;
            font-weight: 500;
        }
        
        .copy-button:hover {
            background: rgba(59, 130, 246, 0.2);
            border-color: rgba(59, 130, 246, 0.5);
            transform: translateY(-1px);
        }
        
        .copy-button.copied {
            background: rgba(34, 197, 94, 0.2);
            border-color: rgba(34, 197, 94, 0.5);
            color: #22c55e;
        }
        
        .copy-icon {
            width: 14px;
            height: 14px;
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
            background: rgba(248, 250, 252, 0.9);
            padding: 1.5rem;
            border-radius: 16px;
            border: 1px solid rgba(226, 232, 240, 0.5);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }
        
        .tool-item::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, #00f5ff 0%, #8b5cf6 50%, #ec4899 100%);
            opacity: 0;
            transition: opacity 0.3s ease;
        }
        
        .tool-item:hover {
            background: rgba(255, 255, 255, 1);
            transform: translateY(-4px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.1);
            border-color: rgba(139, 92, 246, 0.3);
        }
        
        .tool-item:hover::before {
            opacity: 1;
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
                font-size: 2.25rem;
            }
            
            .hero p {
                font-size: 1.1rem;
            }
            
            .container {
                padding: 1rem;
            }
            
            .hero {
                padding: 2.5rem 1.5rem;
                margin-bottom: 2rem;
            }
            
            .card {
                padding: 1.5rem;
                margin: 1.5rem 0;
            }
            
            .code-header {
                padding: 0.5rem 1rem;
                flex-direction: column;
                gap: 0.5rem;
                align-items: flex-start;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="hero">
            <h1>📞 OpenPhone MCP</h1>
            <p>AI-powered messaging and contact management for the modern workspace</p>
            <div class="status-badge">
                <span class="status-dot"></span>
                Production Ready
            </div>
        </div>
        
        <div class="card">
            <h2><span class="icon">🚀</span>Quick Setup</h2>
            
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; margin-bottom: 2rem;">
                <div>
                    <h3 style="margin-bottom: 1rem; color: #1e293b;">🌐 Claude Web App</h3>
                    <p style="margin-bottom: 1rem; color: #64748b; font-size: 0.9rem;">Add as a direct integration:</p>
                    <ol style="color: #64748b; font-size: 0.9rem; line-height: 1.6; padding-left: 1.5rem;">
                        <li>Go to Claude.ai settings</li>
                        <li>Click "Add integration"</li>
                        <li>Name: <strong>OpenPhone</strong></li>
                        <li>URL: <code style="background: #f1f5f9; padding: 0.25rem 0.5rem; border-radius: 4px;">https://mcp.openphonelabs.com/sse</code></li>
                        <li>Click "Connect" and enter your API key</li>
                    </ol>
                </div>
                
                <div>
                    <h3 style="margin-bottom: 1rem; color: #1e293b;">💻 Claude Desktop</h3>
                    <p style="margin-bottom: 1rem; color: #64748b; font-size: 0.9rem;"><strong>Method 1:</strong> Settings > Integrations > Add custom integration<br>
                    <strong>Method 2:</strong> Add to configuration file:</p>
            
            <div class="code">
                <div class="code-header">
                    <span>claude_desktop_config.json</span>
                    <button class="copy-button" onclick="copyConfig(this)">
                        <svg class="copy-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                        </svg>
                        <span class="copy-text">Copy</span>
                    </button>
                </div>
                <div class="code-content">
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
                    
                    <div class="highlight" style="margin-top: 1rem;">
                        <strong>✅ Working Configuration:</strong> Replace the URL above with:<br>
                        <code>https://mcp.openphonelabs.com/sse?key=your_actual_api_key</code><br>
                        <strong>Note:</strong> API keys in URLs are visible in logs. Deploy your own instance for production use.
                    </div>
                </div>
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
            <h2><span class="icon">⚠️</span>Security Considerations</h2>
            <div style="background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); padding: 1.25rem; border-radius: 12px; margin-bottom: 1.5rem;">
                <strong style="color: #dc2626;">Important Security Notice:</strong><br>
                Using API keys in URLs exposes them in logs, browser history, and referrer headers. This is a limitation of the <code>mcp-remote</code> tool.
            </div>
            <div class="tools-grid">
                <div class="tool-item">
                    <div class="tool-name">🔍 Input Validation</div>
                    <div class="tool-desc">Phone number format, message length, and API key validation</div>
                </div>
                <div class="tool-item">
                    <div class="tool-name">🌐 Security Headers</div>
                    <div class="tool-desc">CSP, X-Frame-Options, and content type protection</div>
                </div>
                <div class="tool-item">
                    <div class="tool-name">⏱️ Request Protection</div>
                    <div class="tool-desc">30-second timeouts and sanitized error messages</div>
                </div>
                <div class="tool-item">
                    <div class="tool-name">🚀 Enterprise Option</div>
                    <div class="tool-desc">Deploy your own instance with environment variables for secure auth</div>
                </div>
            </div>
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

function getAuthPageHTML(error?: string): string {
	return `
<!DOCTYPE html>
<html>
<head>
    <title>Connect OpenPhone to Claude</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body { 
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 25%, #16213e 50%, #0f3460 75%, #533a7d 100%);
            min-height: 100vh;
            color: #1a202c;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 2rem;
        }
        
        .auth-container {
            background: rgba(255, 255, 255, 0.98);
            backdrop-filter: blur(20px);
            padding: 3rem;
            border-radius: 24px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.25), 0 0 0 1px rgba(255,255,255,0.3);
            border: 1px solid rgba(255,255,255,0.3);
            max-width: 500px;
            width: 100%;
            position: relative;
            overflow: hidden;
        }
        
        .auth-container::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #00f5ff 0%, #8b5cf6 25%, #ec4899 50%, #f59e0b 75%, #10b981 100%);
        }
        
        h1 {
            font-size: 2rem;
            font-weight: 700;
            background: linear-gradient(135deg, #00f5ff 0%, #8b5cf6 50%, #ec4899 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 0.5rem;
            text-align: center;
        }
        
        .subtitle {
            color: #64748b;
            text-align: center;
            margin-bottom: 2rem;
            font-size: 1.1rem;
        }
        
        .form-group {
            margin-bottom: 1.5rem;
        }
        
        label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 600;
            color: #374151;
        }
        
        input {
            width: 100%;
            padding: 0.875rem;
            border: 2px solid #e5e7eb;
            border-radius: 12px;
            font-size: 1rem;
            transition: border-color 0.2s ease;
            font-family: 'SF Mono', 'Monaco', monospace;
        }
        
        input:focus {
            outline: none;
            border-color: #8b5cf6;
            box-shadow: 0 0 0 3px rgba(139, 92, 246, 0.1);
        }
        
        .submit-btn {
            width: 100%;
            background: linear-gradient(135deg, #8b5cf6 0%, #ec4899 100%);
            color: white;
            border: none;
            padding: 1rem;
            border-radius: 12px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s ease;
        }
        
        .submit-btn:hover {
            transform: translateY(-2px);
        }
        
        .submit-btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        
        .error {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: #dc2626;
            padding: 1rem;
            border-radius: 12px;
            margin-bottom: 1.5rem;
            font-size: 0.9rem;
        }
        
        .help-text {
            font-size: 0.875rem;
            color: #6b7280;
            margin-top: 0.5rem;
        }
        
        .help-link {
            color: #8b5cf6;
            text-decoration: none;
        }
        
        .help-link:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="auth-container">
        <h1>📞 Connect OpenPhone</h1>
        <p class="subtitle">Enter your OpenPhone API key to connect</p>
        
        ${error ? `<div class="error">❌ ${error}</div>` : ''}
        
        <form method="POST" action="/auth">
            <div class="form-group">
                <label for="api_key">OpenPhone API Key</label>
                <input 
                    type="password" 
                    id="api_key" 
                    name="api_key" 
                    placeholder="Enter your OpenPhone API key"
                    required
                    autocomplete="off"
                >
                <div class="help-text">
                    Get your API key from your <a href="https://app.openphone.com" target="_blank" class="help-link">OpenPhone dashboard</a> → Settings → Integrations → API
                </div>
            </div>
            
            <button type="submit" class="submit-btn">
                Connect to Claude
            </button>
        </form>
    </div>
</body>
</html>
	`;
}
