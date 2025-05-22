import { OpenPhoneMCPAgent } from "./openphone-mcp-agent.js";

export { OpenPhoneMCPAgent };

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext) {
		const url = new URL(request.url);

		// Handle OAuth authorization endpoint
		if (url.pathname === "/authorize") {
			const clientId = env.GITHUB_CLIENT_ID;
			if (!clientId) {
				return new Response("GitHub OAuth not configured", { status: 500 });
			}
			
			// Redirect to GitHub OAuth
			const authUrl = new URL("https://github.com/login/oauth/authorize");
			authUrl.searchParams.set("client_id", clientId);
			authUrl.searchParams.set("redirect_uri", `${url.origin}/callback`);
			authUrl.searchParams.set("scope", "user:email");
			
			return Response.redirect(authUrl.toString(), 302);
		}

		// Handle OAuth callback
		if (url.pathname === "/callback") {
			const code = url.searchParams.get("code");
			if (!code) {
				return new Response("No authorization code provided", { status: 400 });
			}

			// Exchange code for access token
			const tokenResponse = await fetch("https://github.com/login/oauth/access_token", {
				method: "POST",
				headers: {
					"Accept": "application/json",
					"Content-Type": "application/x-www-form-urlencoded",
				},
				body: new URLSearchParams({
					client_id: env.GITHUB_CLIENT_ID,
					client_secret: env.GITHUB_CLIENT_SECRET,
					code: code,
				}),
			});

			const tokenData = await tokenResponse.json() as { access_token?: string };
			
			return new Response(`
				<html>
					<body>
						<h1>OAuth Success!</h1>
						<p>You can now close this tab and return to the MCP Inspector.</p>
						<script>
							// Store the token in localStorage for the MCP client
							localStorage.setItem('github_token', '${tokenData.access_token || ''}');
							window.close();
						</script>
					</body>
				</html>
			`, {
				headers: { "Content-Type": "text/html" },
			});
		}

		// Handle MCP SSE endpoint
		if (url.pathname === "/sse" || url.pathname === "/sse/message") {
			return OpenPhoneMCPAgent.serveSSE("/sse").fetch(request, env, ctx);
		}

		// Handle MCP endpoint
		if (url.pathname === "/mcp") {
			return OpenPhoneMCPAgent.serve("/mcp").fetch(request, env, ctx);
		}

		return new Response("Not found", { status: 404 });
	},
};
