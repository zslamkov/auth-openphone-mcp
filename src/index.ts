import { OpenPhoneMCPAgent } from "./openphone-mcp-agent.js";

export { OpenPhoneMCPAgent };

// OAuth 2.1 + PKCE implementation for Claude Desktop
interface OAuthClient {
	client_id: string;
	client_secret?: string;
	redirect_uris: string[];
	scope?: string;
	created_at: number;
}

interface AuthorizationCode {
	code: string;
	client_id: string;
	redirect_uri: string;
	scope: string;
	code_challenge: string;
	code_challenge_method: string;
	expires_at: number;
	api_key?: string;
}

// Environment bindings for Cloudflare Workers
type Env = {
	OPENPHONE_API_KEY?: string;
	OAUTH_SECRET_KEY?: string;
  SEGMENT_WRITE_KEY?: string;
}

// In-memory storage for demo (in production, use Durable Objects or external storage)
const clients = new Map<string, OAuthClient>();



async function sha256(plain: string): Promise<string> {
	const encoder = new TextEncoder();
	const data = encoder.encode(plain);
	const hash = await crypto.subtle.digest('SHA-256', data);
	return btoa(String.fromCharCode(...new Uint8Array(hash)))
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=/g, '');
}

// Extract user query from MCP protocol messages
function extractUserQueryFromMCPMessage(mcpMessage: any): string | undefined {
	try {
		// Handle different MCP message types that might contain user context

		// Tools call message - this contains the actual tool call with parameters
		if (mcpMessage.method === 'tools/call' && mcpMessage.params?.arguments) {
			// Check if the tool call already has a userQuery parameter
			try {
				const args = typeof mcpMessage.params.arguments === 'string'
					? JSON.parse(mcpMessage.params.arguments)
					: mcpMessage.params.arguments;

				if (args.userQuery) {
					return args.userQuery;
				}
			} catch (parseError) {
				// JSON parsing failed, continue to other methods
			}
		}

		// Completion request - this might contain the conversation context
		if (mcpMessage.method === 'completion/complete' || mcpMessage.method === 'sampling/createMessage') {
			// Look for user messages in the conversation
			const messages = mcpMessage.params?.messages || mcpMessage.params?.prompt?.messages || [];

			// Find the most recent user message
			for (let i = messages.length - 1; i >= 0; i--) {
				const message = messages[i];
				if (message.role === 'user' && message.content) {
					// Extract text content from various formats
					if (typeof message.content === 'string') {
						return message.content.trim();
					} else if (Array.isArray(message.content)) {
						// Handle message content arrays
						const textContent = message.content
							.filter((item: any) => item.type === 'text')
							.map((item: any) => item.text)
							.join(' ');
						if (textContent.trim()) {
							return textContent.trim();
						}
					}
				}
			}
		}

		// Generic message with text content
		if (mcpMessage.content && typeof mcpMessage.content === 'string') {
			return mcpMessage.content.trim();
		}

		// Check for any user-related text in common fields
		if (mcpMessage.query && typeof mcpMessage.query === 'string') {
			return mcpMessage.query.trim();
		}

		if (mcpMessage.text && typeof mcpMessage.text === 'string') {
			return mcpMessage.text.trim();
		}

		return undefined;
	} catch (e) {
		// Parsing failed, return undefined
		return undefined;
	}
}

// Secure secret key management
function getSecretKey(env: Env): string {
	// Use environment variable if available, fallback to default for backward compatibility
	return env.OAUTH_SECRET_KEY || 'openphone-mcp-auth-secret-2024-fallback';
}

async function createStatelessCode(authData: AuthorizationCode, env: Env): Promise<string> {
	const secretKey = getSecretKey(env);
	// Create a signed payload
	const payload = {
		...authData,
		signature: await sha256(secretKey + JSON.stringify(authData))
	};
	
	// Base64 encode the payload
	const encoded = btoa(JSON.stringify(payload))
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=/g, '');
	
	return encoded;
}

async function validateStatelessCode(code: string, env: Env): Promise<AuthorizationCode | null> {
	try {
		const secretKey = getSecretKey(env);
		// Decode the payload
		const decoded = atob(code.replace(/-/g, '+').replace(/_/g, '/'));
		const payload = JSON.parse(decoded);
		
		// Extract signature and verify
		const { signature, ...authData } = payload;
		const expectedSignature = await sha256(secretKey + JSON.stringify(authData));
		
		if (signature !== expectedSignature) {
			return null;
		}
		
		// Check expiration
		if (authData.expires_at < Date.now()) {
			return null;
		}
		
		return authData;
	} catch (error) {
		return null;
	}
}

// Stateless access token implementation
async function createStatelessAccessToken(api_key: string, scope: string, env: Env, expires_in = 3600): Promise<string> {
	const secretKey = getSecretKey(env);
	const tokenData = {
		api_key,
		scope,
		exp: Math.floor(Date.now() / 1000) + expires_in, // Expiration as Unix timestamp
		iat: Math.floor(Date.now() / 1000) // Issued at
	};
	
	// Create signature
	const tokenString = JSON.stringify(tokenData);
	const signature = await sha256(secretKey + tokenString);
	
	// Create final payload with signature
	const payload = {
		...tokenData,
		sig: signature
	};
	
	// Base64 URL encode
	const encoded = btoa(JSON.stringify(payload))
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=/g, '');
	
	return encoded;
}

async function validateStatelessAccessToken(token: string, env: Env): Promise<{ api_key: string; scope: string } | null> {
	try {
		const secretKey = getSecretKey(env);
		// Decode the payload
		const decoded = atob(token.replace(/-/g, '+').replace(/_/g, '/'));
		const payload = JSON.parse(decoded);
		
		// Extract signature and verify
		const { sig, ...tokenData } = payload;
		const expectedSignature = await sha256(secretKey + JSON.stringify(tokenData));
		
		if (sig !== expectedSignature) {
			return null;
		}
		
		// Check expiration
		const now = Math.floor(Date.now() / 1000);
		if (tokenData.exp < now) {
			return null;
		}
		
		return { api_key: tokenData.api_key, scope: tokenData.scope };
	} catch (error) {
		return null;
	}
}

async function handleOAuthWellKnown(request: Request, url: URL): Promise<Response> {
	const baseUrl = `${url.protocol}//${url.host}`;
	
	const metadata = {
		issuer: baseUrl,
		authorization_endpoint: `${baseUrl}/authorize`,
		token_endpoint: `${baseUrl}/token`,
		registration_endpoint: `${baseUrl}/register`,
		scopes_supported: ["openphone:read", "openphone:write", "openphone:admin"],
		response_types_supported: ["code"],
		grant_types_supported: ["authorization_code"],
		code_challenge_methods_supported: ["S256"],
		token_endpoint_auth_methods_supported: ["none", "client_secret_basic"],
		response_modes_supported: ["query"],
		subject_types_supported: ["public"],
		// Add cache-busting timestamp
		_cache_bust: Date.now()
	};

	return new Response(JSON.stringify(metadata, null, 2), {
		headers: {
			'Content-Type': 'application/json',
			'Access-Control-Allow-Origin': '*',
			'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
			'Access-Control-Allow-Headers': 'Content-Type, Authorization, mcp-protocol-version',
			'Cache-Control': 'no-cache, no-store, must-revalidate',
			'Pragma': 'no-cache',
			'Expires': '0'
		}
	});
}

async function handleOAuthRegister(request: Request, url: URL, env: Env): Promise<Response> {
	if (request.method !== 'POST') {
		return new Response('Method not allowed', { status: 405 });
	}

	try {
		const body = await request.json() as any;
		
		// Use a fixed client ID that persists across worker restarts
		const clientId = 'openphone-mcp-client';
		const clientSecret = 'not-needed-for-pkce';

		// Accept callback URLs for both Claude and ChatGPT
		const redirectUris = [
			'https://claude.ai/api/mcp/auth_callback',
			'https://chatgpt.com/oauth/callback',
			'https://chat.openai.com/oauth/callback',
			'urn:ietf:wg:oauth:2.0:oob'  // For out-of-band flow
		];

		const client: OAuthClient = {
			client_id: clientId,
			client_secret: clientSecret,
			redirect_uris: redirectUris,
			scope: 'openphone:read openphone:write openphone:admin',
			created_at: Date.now()
		};

		clients.set(clientId, client);

		const response = {
			client_id: clientId,
			client_secret: clientSecret,
			client_secret_expires_at: 0, // Never expires
			redirect_uris: client.redirect_uris,
			grant_types: ["authorization_code"],
			response_types: ["code"],
			token_endpoint_auth_method: "none" // PKCE doesn't need client secret
		};

		return new Response(JSON.stringify(response), {
			status: 201,
			headers: {
				'Content-Type': 'application/json',
				'Access-Control-Allow-Origin': '*',
				'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
				'Access-Control-Allow-Headers': 'Content-Type, Authorization, mcp-protocol-version',
				'Cache-Control': 'no-cache, no-store, must-revalidate',
				'Pragma': 'no-cache',
				'Expires': '0'
			}
		});
	} catch (error) {
		return new Response(JSON.stringify({ error: 'invalid_request' }), {
			status: 400,
			headers: { 'Content-Type': 'application/json' }
		});
	}
}

async function handleOAuthAuthorize(request: Request, url: URL, env: Env): Promise<Response> {
	console.log('🔧 handleOAuthAuthorize called');
	console.log('🔧 Request URL:', request.url);
	console.log('🔧 Request method:', request.method);
	
	const params = url.searchParams;
	const clientId = params.get('client_id');
	const redirectUri = params.get('redirect_uri');
	const responseType = params.get('response_type');
	const scope = params.get('scope') || 'openphone:read openphone:write';
	const state = params.get('state');
	const codeChallenge = params.get('code_challenge');
	const codeChallengeMethod = params.get('code_challenge_method');
	
	console.log('🔧 Parsed params:', { clientId, redirectUri, responseType, scope, state, codeChallenge, codeChallengeMethod });

	// Validate required parameters
	if (!clientId || !redirectUri || responseType !== 'code' || !codeChallenge || codeChallengeMethod !== 'S256') {
		const errorUrl = new URL(redirectUri || `${url.protocol}//${url.host}/error`);
		errorUrl.searchParams.set('error', 'invalid_request');
		if (state) errorUrl.searchParams.set('state', state);
		return Response.redirect(errorUrl.toString(), 302);
	}

	// Auto-recreate client if not found (handles cold starts)
	let client = clients.get(clientId);
	
	if (!client) {
		// Auto-register so the flow survives new isolates
		client = {
			client_id: clientId,
			client_secret: 'not-needed-for-pkce',
			redirect_uris: [redirectUri], // Use the redirect URI from the request
			scope: scope,
			created_at: Date.now()
		};
		clients.set(clientId, client);
	} else {
		// If client exists but doesn't have this redirect URI, add it
		if (!client.redirect_uris.includes(redirectUri)) {
			client.redirect_uris.push(redirectUri);
			clients.set(clientId, client);
		}
	}
	
	
	if (!client || !client.redirect_uris.includes(redirectUri)) {
		const errorUrl = new URL(redirectUri);
		errorUrl.searchParams.set('error', 'invalid_client');
		if (state) errorUrl.searchParams.set('state', state);
		return Response.redirect(errorUrl.toString(), 302);
	}

	if (request.method === 'GET') {
		// Show authorization form
		return new Response(getAuthorizationPageHTML(clientId, redirectUri, scope, state, codeChallenge, codeChallengeMethod), {
			headers: { 
				'Content-Type': 'text/html',
				'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' fonts.googleapis.com; font-src fonts.gstatic.com",
				'X-Frame-Options': 'DENY',
				'X-Content-Type-Options': 'nosniff'
			}
		});
	}

	if (request.method === 'POST') {
		// Handle authorization decision
		const formData = await request.formData();
		const apiKey = formData.get('api_key') as string;
		const approved = formData.get('approved') === 'true';
		
		console.log('Form submission received:', { approved, apiKeyLength: apiKey?.length, redirectUri });

		if (!approved) {
			const errorUrl = new URL(redirectUri);
			errorUrl.searchParams.set('error', 'access_denied');
			if (state) errorUrl.searchParams.set('state', state);
			return Response.redirect(errorUrl.toString(), 302);
		}

		if (!apiKey?.trim()) {
			return new Response(getAuthorizationPageHTML(clientId, redirectUri, scope, state, codeChallenge, codeChallengeMethod, 'API key is required'), {
				status: 400,
				headers: { 'Content-Type': 'text/html' }
			});
		}

		// Validate API key
		try {
			const trimmedApiKey = apiKey.trim();
			
			// Basic format validation
			if (trimmedApiKey.length < 16 || trimmedApiKey.length > 128) {
				return new Response(getAuthorizationPageHTML(clientId, redirectUri, scope, state, codeChallenge, codeChallengeMethod, 'API key must be 16-128 characters long'), {
					status: 400,
					headers: { 'Content-Type': 'text/html' }
				});
			}

			if (!/^[a-zA-Z0-9._-]+$/.test(trimmedApiKey)) {
				return new Response(getAuthorizationPageHTML(clientId, redirectUri, scope, state, codeChallenge, codeChallengeMethod, 'API key contains invalid characters'), {
					status: 400,
					headers: { 'Content-Type': 'text/html' }
				});
			}

			const testResponse = await fetch('https://api.openphone.com/v1/phone-numbers', {
				headers: {
					'Authorization': trimmedApiKey,
					'Content-Type': 'application/json'
				},
				signal: AbortSignal.timeout(10000) // 10 second timeout
			});

			if (!testResponse.ok) {
				// More specific error messages based on status code
				let errorMessage = 'Invalid API key';
				if (testResponse.status === 401) {
					errorMessage = 'API key is invalid or expired';
				} else if (testResponse.status === 403) {
					errorMessage = 'API key does not have required permissions';
				} else if (testResponse.status === 429) {
					errorMessage = 'Too many API requests. Please try again later';
				}
				
				return new Response(getAuthorizationPageHTML(clientId, redirectUri, scope, state, codeChallenge, codeChallengeMethod, errorMessage), {
					status: 400,
					headers: { 'Content-Type': 'text/html' }
				});
			}
		} catch (error) {
			// More specific error handling
			let errorMessage = 'Failed to validate API key';
			if (error instanceof Error) {
				if (error.name === 'AbortError') {
					errorMessage = 'API validation timed out. Please try again';
				} else if (error.message.includes('fetch')) {
					errorMessage = 'Network error during API validation';
				}
			}
			
			return new Response(getAuthorizationPageHTML(clientId, redirectUri, scope, state, codeChallenge, codeChallengeMethod, errorMessage), {
				status: 500,
				headers: { 'Content-Type': 'text/html' }
			});
		}

		// Generate stateless authorization code
		const authCode: AuthorizationCode = {
			code: '', // Will be set by createStatelessCode
			client_id: clientId,
			redirect_uri: redirectUri,
			scope,
			code_challenge: codeChallenge,
			code_challenge_method: codeChallengeMethod,
			expires_at: Date.now() + 600000, // 10 minutes
			api_key: apiKey.trim()
		};

		const code = await createStatelessCode(authCode, env);
		authCode.code = code; // Set the actual code value

		console.log('Returning success page with code:', code);
		
		// Always show success page for browser-based OAuth form submissions
		// This handles the user-facing portion where they need to see confirmation
		// The actual OAuth flow continues programmatically in the background
		const response: any = { code };
		if (state) response.state = state;
		
		const successHTML = getSuccessPageHTML(JSON.stringify(response), redirectUri, state);
		return new Response(successHTML, {
			headers: { 
				'Content-Type': 'text/html',
				'Access-Control-Allow-Origin': '*',
				'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
				'Access-Control-Allow-Headers': 'Content-Type, Authorization',
				'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' fonts.googleapis.com; font-src fonts.gstatic.com; connect-src 'self'",
				'X-Frame-Options': 'SAMEORIGIN',
				'X-Content-Type-Options': 'nosniff'
			}
		});
	}

	return new Response('Method not allowed', { status: 405 });
}

async function handleOAuthToken(request: Request, url: URL, env: Env): Promise<Response> {
	console.log('🔧 handleOAuthToken called');
	console.log('🔧 Request method:', request.method);
	console.log('🔧 Request URL:', request.url);
	
	if (request.method !== 'POST') {
		console.log('❌ Invalid method:', request.method);
		return new Response(JSON.stringify({ error: 'invalid_request' }), {
			status: 405,
			headers: { 'Content-Type': 'application/json' }
		});
	}

	try {
		// Parse x-www-form-urlencoded body (OAuth standard)
		const bodyText = await request.text();
		console.log('🔧 Request body:', bodyText);
		const params = new URLSearchParams(bodyText);

		const grantType = params.get('grant_type');
		const code = params.get('code') as string;
		const redirectUri = params.get('redirect_uri') as string;
		const clientId = params.get('client_id') as string;
		const codeVerifier = params.get('code_verifier') as string;
		
		console.log('🔧 Parsed params:', { grantType, code: code ? 'PRESENT' : 'MISSING', redirectUri, clientId, codeVerifier: codeVerifier ? 'PRESENT' : 'MISSING' });


		if (grantType !== 'authorization_code') {
			console.log('❌ Invalid grant type:', grantType);
			return new Response(JSON.stringify({ error: 'unsupported_grant_type' }), {
				status: 400,
				headers: { 
					'Content-Type': 'application/json',
					'Access-Control-Allow-Origin': '*',
					'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
					'Access-Control-Allow-Headers': 'Content-Type, Authorization, mcp-protocol-version'
				}
			});
		}

		// Validate stateless authorization code
		console.log('🔧 Validating authorization code...');
		const authCode = await validateStatelessCode(code, env);
		
		if (!authCode) {
			console.log('❌ Invalid authorization code');
			return new Response(JSON.stringify({ error: 'invalid_grant' }), {
				status: 400,
				headers: { 
					'Content-Type': 'application/json',
					'Access-Control-Allow-Origin': '*',
					'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
					'Access-Control-Allow-Headers': 'Content-Type, Authorization, mcp-protocol-version'
				}
			});
		}
		
		console.log('✅ Authorization code validated successfully');

		// Validate PKCE
		console.log('🔧 Validating PKCE...');
		const expectedChallenge = await sha256(codeVerifier);
		console.log('🔧 Expected challenge:', expectedChallenge);
		console.log('🔧 Actual challenge:', authCode.code_challenge);
		if (expectedChallenge !== authCode.code_challenge) {
			console.log('❌ PKCE validation failed');
			return new Response(JSON.stringify({ error: 'invalid_grant' }), {
				status: 400,
				headers: { 
					'Content-Type': 'application/json',
					'Access-Control-Allow-Origin': '*',
					'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
					'Access-Control-Allow-Headers': 'Content-Type, Authorization, mcp-protocol-version'
				}
			});
		}
		
		console.log('✅ PKCE validation successful');

		// Validate other parameters
		console.log('🔧 Validating other parameters...');
		console.log('🔧 Expected client_id:', authCode.client_id, 'Actual:', clientId);
		console.log('🔧 Expected redirect_uri:', authCode.redirect_uri, 'Actual:', redirectUri);
		
		// For PKCE flows, client_id can be omitted from token request (OAuth 2.1 spec)
		const clientIdValid = !clientId || authCode.client_id === clientId;
		const redirectUriValid = authCode.redirect_uri === redirectUri;
		
		if (!clientIdValid || !redirectUriValid) {
			console.log('❌ Parameter validation failed');
			console.log('❌ client_id valid:', clientIdValid);
			console.log('❌ redirect_uri valid:', redirectUriValid);
			return new Response(JSON.stringify({ error: 'invalid_grant' }), {
				status: 400,
				headers: { 
					'Content-Type': 'application/json',
					'Access-Control-Allow-Origin': '*',
					'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
					'Access-Control-Allow-Headers': 'Content-Type, Authorization, mcp-protocol-version'
				}
			});
		}
		
		console.log('✅ Parameter validation successful');

		// Generate stateless access token
		console.log('🔧 Generating access token...');
		const accessToken = await createStatelessAccessToken(authCode.api_key!, authCode.scope, env, 3600);

		const response = {
			access_token: accessToken,
			token_type: 'Bearer',
			expires_in: 3600,
			scope: authCode.scope
		};

		console.log('✅ Token exchange successful');
		return new Response(JSON.stringify(response), {
			headers: {
				'Content-Type': 'application/json',
				'Access-Control-Allow-Origin': '*',
				'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
				'Access-Control-Allow-Headers': 'Content-Type, Authorization, mcp-protocol-version'
			}
		});
	} catch (error) {
		return new Response(JSON.stringify({ error: 'invalid_request' }), {
			status: 400,
			headers: { 'Content-Type': 'application/json' }
		});
	}
}

async function authGate(request: Request, env: Env): Promise<{ response?: Response; api_key?: string }> {
	// Allow CORS pre-flight
	if (request.method === 'OPTIONS') return {};
	
	const authHeader = request.headers.get('authorization');
	if (!authHeader?.startsWith('Bearer ')) {
		return {
			response: new Response('Unauthorized', {
				status: 401,
				headers: { 
					'WWW-Authenticate': 'Bearer realm="OpenPhone"',
					'Access-Control-Allow-Origin': '*',
					'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
					'Access-Control-Allow-Headers': 'Content-Type, Authorization, mcp-protocol-version'
				}
			})
		};
	}
	
	const token = authHeader.slice(7);
	
	const tokenData = await validateStatelessAccessToken(token, env);
	if (!tokenData) {
		return {
			response: new Response('Unauthorized', {
				status: 401,
				headers: { 
					'WWW-Authenticate': 'Bearer error="invalid_token"',
					'Access-Control-Allow-Origin': '*',
					'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
					'Access-Control-Allow-Headers': 'Content-Type, Authorization, mcp-protocol-version'
				}
			})
		};
	}
	// Return the API key for downstream handlers
	return { api_key: tokenData.api_key };
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
					'Access-Control-Allow-Headers': 'Content-Type, Authorization, mcp-protocol-version',
					'Access-Control-Max-Age': '86400',
				}
			});
		}

		// Handle OAuth 2.1 + PKCE endpoints for Claude Desktop
		if (url.pathname === "/.well-known/oauth-authorization-server" || url.pathname === "/.well-known/oauth-authorization-server/sse") {
            // OAuth well-known endpoint accessed
			return handleOAuthWellKnown(request, url);
		}
		
		// Handle OAuth protected resource endpoints (required by MCP protocol)
		if (url.pathname === "/.well-known/oauth-protected-resource" || url.pathname === "/.well-known/oauth-protected-resource/sse") {
			console.log('🔧 OAuth protected resource endpoint accessed');
			return new Response(JSON.stringify({
				resource: "openphone-mcp",
				scopes: ["openphone:read", "openphone:write", "openphone:admin"]
			}), {
				headers: {
					'Content-Type': 'application/json',
					'Access-Control-Allow-Origin': '*',
					'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
					'Access-Control-Allow-Headers': 'Content-Type, Authorization, mcp-protocol-version',
					'Cache-Control': 'no-cache, no-store, must-revalidate',
					'Pragma': 'no-cache',
					'Expires': '0'
				}
			});
		}
		
		if (url.pathname === "/register") {
            // OAuth register endpoint accessed
			return handleOAuthRegister(request, url, env);
		}
		
		if (url.pathname === "/authorize") {
            // OAuth authorize endpoint accessed
			return handleOAuthAuthorize(request, url, env);
		}
		
		if (url.pathname === "/token") {
            // OAuth token endpoint accessed
			return handleOAuthToken(request, url, env);
		}

		// Debug endpoint to test Segment connectivity
		if (url.pathname === "/debug/segment") {
			const writeKey = env.SEGMENT_WRITE_KEY;
			if (!writeKey) {
				return new Response(JSON.stringify({ ok: false, error: 'SEGMENT_WRITE_KEY not set' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
			}
			const auth = 'Basic ' + btoa(`${writeKey}:`);
			const body = {
				userId: 'debug',
				event: 'debug_tool_call',
				properties: { toolName: 'debug', success: true },
				context: { library: { name: 'openphone-mcp', version: '1.0.0' } },
				timestamp: new Date().toISOString()
			};
			const res = await fetch('https://api.segment.io/v1/track', {
				method: 'POST',
				headers: { 'Authorization': auth, 'Content-Type': 'application/json' },
				body: JSON.stringify(body)
			});
			const txt = await res.text();
			return new Response(JSON.stringify({ ok: res.ok, status: res.status, body: txt }), { headers: { 'Content-Type': 'application/json' } });
		}

		// Extract headers for secure API key transmission (for non-protected endpoints)
		const headers = Object.fromEntries(request.headers.entries());
		const searchParams = Object.fromEntries(url.searchParams.entries());
		ctx.props = { ...headers, ...searchParams };


		// Handle MCP SSE endpoint (protected)
		if (url.pathname === "/sse" || url.pathname === "/sse/message") {
			const userAgent = request.headers.get('user-agent') || 'unknown';
			const isClaudeDesktop = userAgent.includes('Claude-User');
			const isChatGPT = userAgent.includes('ChatGPT') || userAgent.includes('OpenAI');
			
            // SSE endpoint accessed
			
			if (isClaudeDesktop) {
                // CLAUDE DESKTOP REQUEST DETECTED
			}
			
			if (isChatGPT) {
                // CHATGPT REQUEST DETECTED
			}
			
			// Check if there's a request body
			const bodyText = request.method === 'POST' ? await request.text() : '';
            // Body consumed

			// Parse MCP messages to extract user queries
			let userQuery: string | undefined;
			if (bodyText) {
				try {
					const mcpMessage = JSON.parse(bodyText);
					userQuery = extractUserQueryFromMCPMessage(mcpMessage);
				} catch (e) {
					// Not JSON or parsing failed, continue without user query
				}
			}

			// Create a new request with the body if it was consumed
			const newRequest = request.method === 'POST' ?
				new Request(request.url, {
					method: request.method,
					headers: request.headers,
					body: bodyText
				}) : request;

			const authResult = await authGate(newRequest, env);
			if (authResult.response) {
				return authResult.response;
			}

			// Add API key and user query to headers for the agent
			if (authResult.api_key) {
				headers['x-openphone-api-key'] = authResult.api_key;
			}
			if (userQuery) {
				headers['x-user-query'] = userQuery;
			}
			ctx.props = { ...headers, ...searchParams };
			
			const response = await OpenPhoneMCPAgent.serveSSE("/sse").fetch(newRequest, env, ctx);
			
			// Add CORS headers to the response
			const newHeaders = new Headers(response.headers);
			newHeaders.set('Access-Control-Allow-Origin', '*');
			newHeaders.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
			newHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, mcp-protocol-version');
			
			return new Response(response.body, {
				status: response.status,
				statusText: response.statusText,
				headers: newHeaders
			});
		}

		// Handle MCP endpoint (protected)
		if (url.pathname === "/mcp") {
			const authResult = await authGate(request, env);
			if (authResult.response) return authResult.response;
			
			// Add API key to headers for the agent
			if (authResult.api_key) {
				headers['x-openphone-api-key'] = authResult.api_key;
				ctx.props = { ...headers, ...searchParams };
			}
			
			const response = await OpenPhoneMCPAgent.serve("/mcp").fetch(request, env, ctx);
			
			// Add CORS headers to the response
			const newHeaders = new Headers(response.headers);
			newHeaders.set('Access-Control-Allow-Origin', '*');
			newHeaders.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
			newHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, mcp-protocol-version');
			
			return new Response(response.body, {
				status: response.status,
				statusText: response.statusText,
				headers: newHeaders
			});
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
        :root {
            --bg: #0f1220;
            --surface: #171a2a;
            --card: #1c2033;
            --muted: #94a3b8;
            --text: #e5e7eb;
            --heading: #f8fafc;
            --accent: #f97316;
            --accent-2: #22c55e;
            --border: #2b3149;
            --shadow: 0 6px 20px rgba(0,0,0,0.25);
        }
        [data-theme="light"] {
            --bg: #f8fafc;
            --surface: #ffffff;
            --card: #ffffff;
            --muted: #475569;
            --text: #0f172a;
            --heading: #0f172a;
            --accent: #ea580c;
            --accent-2: #16a34a;
            --border: #e2e8f0;
            --shadow: 0 6px 18px rgba(2,6,23,0.08);
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        html, body { height: 100%; }
        body {
            font-family: 'Inter', ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, 'Helvetica Neue', Arial, 'Apple Color Emoji', 'Segoe UI Emoji';
            background: var(--bg);
            color: var(--text);
        }
        .header {
            position: sticky; top: 0; z-index: 50;
            backdrop-filter: saturate(140%) blur(8px);
            background: color-mix(in oklab, var(--bg) 85%, transparent);
            border-bottom: 1px solid var(--border);
        }
        .header-inner {
            max-width: 1100px; margin: 0 auto; padding: 0.75rem 1rem;
            display: flex; align-items: center; justify-content: space-between;
        }
        .brand { display: flex; align-items: center; gap: 0.75rem; font-weight: 700; color: var(--heading); }
        .brand .logo { font-size: 1.25rem; }
        .brand small { font-weight: 600; color: var(--muted); }
        .nav { display: flex; align-items: center; gap: 1rem; }
        .nav a {
            color: var(--muted); text-decoration: none; font-weight: 600; font-size: 0.95rem; padding: 0.4rem 0.6rem; border-radius: 8px;
        }
        .nav a:hover { color: var(--heading); background: color-mix(in oklab, var(--card), transparent 65%); }
        .theme-toggle {
            appearance: none; border: 1px solid var(--border); background: var(--surface);
            color: var(--text); border-radius: 10px; padding: 0.4rem 0.6rem; cursor: pointer; font-weight: 600;
        }
        .container { max-width: 1100px; margin: 0 auto; padding: 1.5rem; }

        .hero {
            background: radial-gradient(1200px 300px at 50% -20%, color-mix(in oklab, var(--accent), transparent 75%), transparent 60%), var(--surface);
            border: 1px solid var(--border); border-radius: 16px; padding: 2.5rem; margin: 1.25rem 0 2rem; box-shadow: var(--shadow); position: relative; overflow: hidden;
        }
        .hero h1 { font-size: 2.4rem; letter-spacing: -0.02em; color: var(--heading); font-weight: 800; margin-bottom: 0.5rem; }
        .hero p { color: var(--muted); font-size: 1.05rem; max-width: 720px; }
        .cta { display: flex; gap: 0.6rem; flex-wrap: wrap; margin-top: 1.2rem; }
        .btn { border: 1px solid color-mix(in oklab, var(--accent), var(--border)); background: color-mix(in oklab, var(--accent), transparent 85%); color: var(--accent); padding: 0.55rem 0.9rem; border-radius: 10px; font-weight: 700; cursor: pointer; }
        .btn:hover { background: color-mix(in oklab, var(--accent), transparent 75%); }
        .btn-ghost { border: 1px solid var(--border); background: var(--card); color: var(--text); }
        .btn-ghost:hover { background: color-mix(in oklab, var(--card), transparent 70%); }
        .pill { display: inline-flex; align-items: center; gap: 0.5rem; border: 1px solid color-mix(in oklab, var(--accent-2), var(--border)); background: color-mix(in oklab, var(--accent-2), transparent 85%); color: var(--accent-2); font-weight: 700; padding: 0.4rem 0.65rem; border-radius: 999px; }

        .section { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; margin: 1.25rem 0; box-shadow: var(--shadow); }
        .section h2 { font-size: 1.25rem; color: var(--heading); display: flex; align-items: center; gap: 0.6rem; margin-bottom: 1rem; }
        .muted { color: var(--muted); }

        .tabs { display: flex; gap: 0.5rem; margin-bottom: 0.75rem; }
        [role="tab"] {
            border: 1px solid var(--border); background: var(--surface); color: var(--muted);
            border-radius: 10px; padding: 0.45rem 0.8rem; font-weight: 700; cursor: pointer;
        }
        [role="tab"][aria-selected="true"] { color: var(--heading); border-color: color-mix(in oklab, var(--accent), var(--border)); background: color-mix(in oklab, var(--accent), transparent 90%); }
        [role="tabpanel"][hidden] { display: none; }

        .code { border: 1px solid var(--border); background: #0b1220; border-radius: 10px; overflow: hidden; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
        [data-theme="light"] .code { background: #0f172a; }
        .code-header { display: flex; align-items: center; justify-content: space-between; padding: 0.6rem 0.8rem; border-bottom: 1px solid var(--border); color: #cbd5e1; font-weight: 700; font-size: 0.8rem; }
        .code pre { margin: 0; padding: 0.9rem; color: #e2e8f0; white-space: pre; overflow-x: auto; tab-size: 2; }
        .copy { border: 1px solid var(--border); background: color-mix(in oklab, var(--surface), transparent 0%); color: var(--text); border-radius: 8px; padding: 0.35rem 0.6rem; cursor: pointer; font-weight: 600; }
        .copy:hover { background: color-mix(in oklab, var(--surface), transparent 70%); }

        details.tool { border: 1px solid var(--border); background: var(--surface); border-radius: 10px; padding: 0.9rem 1rem; margin: 0.6rem 0; }
        details.tool > summary { cursor: pointer; list-style: none; display: flex; align-items: center; gap: 0.6rem; font-weight: 700; color: var(--heading); }
        details.tool > summary::-webkit-details-marker { display: none; }
        .badge { display: inline-block; background: var(--accent); color: #fff; padding: 0.15rem 0.5rem; border-radius: 6px; font-size: 0.75rem; font-weight: 700; }
        .example { margin-top: 0.7rem; }

        .grid { display: grid; gap: 1rem; grid-template-columns: repeat(2, minmax(0, 1fr)); }
        @media (max-width: 820px) { .grid { grid-template-columns: 1fr; } }

        .footer { text-align: center; margin-top: 2rem; padding: 1.25rem; color: var(--muted); border-top: 1px solid var(--border); }

        .toast { position: fixed; bottom: 18px; left: 50%; transform: translateX(-50%); background: var(--surface); color: var(--heading); border: 1px solid var(--border); padding: 0.6rem 0.9rem; border-radius: 10px; box-shadow: var(--shadow); font-weight: 700; opacity: 0; pointer-events: none; transition: opacity .2s ease, transform .2s ease; }
        .toast.show { opacity: 1; transform: translateX(-50%) translateY(-6px); }

        .focus-ring { outline: 2px solid color-mix(in oklab, var(--accent), white 10%); outline-offset: 2px; }
    </style>
</head>
<body>
    <header class="header">
        <div class="header-inner">
            <div class="brand">
                <div class="logo">📞</div>
                <div>OpenPhone MCP <small>v1.0.0</small></div>
            </div>
	            <nav class="nav">
	                <a href="#setup">Setup</a>
	                <button class="theme-toggle" id="themeToggle" aria-label="Toggle theme">🌙</button>
	            </nav>
        </div>
    </header>

    <main class="container">
        <section class="hero">
            <div class="pill"><span class="dot" style="width:8px;height:8px;background:var(--accent-2);border-radius:50%;display:inline-block"></span> Production Ready</div>
            <h1>OpenPhone MCP</h1>
            <p>AI-powered messaging and contact management for the modern workspace. Compatible with Claude Desktop and ChatGPT.</p>
            <div class="cta">
                <button class="btn-ghost btn" id="copyUrl">Copy MCP URL</button>
                <button class="btn-ghost btn" id="copyInspector">Copy MCP Inspector cmd</button>
            </div>
        </section>

        <section id="setup" class="section">
            <h2>🚀 Quick Setup</h2>

            <div class="tabs" role="tablist" aria-label="Setup">
                <button role="tab" aria-selected="true" aria-controls="tab-claude" id="tab-claude-btn">Claude Desktop</button>
                <button role="tab" aria-selected="false" aria-controls="tab-chatgpt" id="tab-chatgpt-btn">ChatGPT</button>
            </div>

            <section id="tab-claude" role="tabpanel" aria-labelledby="tab-claude-btn">
                <ol class="muted" style="line-height:1.9; padding-left: 1.25rem;">
                    <li>Open Claude Desktop → Settings → Integrations</li>
                    <li>Click <strong style="color: var(--heading);">Add custom integration</strong></li>
                    <li>Name: <strong style="color: var(--heading);">OpenPhone</strong></li>
                    <li>URL: <code style="background:#0b1220;color:var(--accent);padding:0.2rem 0.4rem;border-radius:6px;border:1px solid var(--border)">https://mcp.openphonelabs.com/sse</code></li>
                    <li>Click Connect and enter your OpenPhone API key</li>
                </ol>

                <p class="muted" style="margin-top:0.6rem">Tip: Claude Desktop may occasionally disconnect — just reconnect.</p>
            </section>

            <section id="tab-chatgpt" role="tabpanel" aria-labelledby="tab-chatgpt-btn" hidden>
                <ol class="muted" style="line-height:1.9; padding-left: 1.25rem;">
                    <li>Open ChatGPT → Settings → Connectors</li>
                    <li>Enable <strong style="color: var(--heading);">Developer mode</strong> (Pro/Plus required)</li>
                    <li>Click <strong style="color: var(--heading);">Add connector</strong></li>
                    <li>Name: <strong style="color: var(--heading);">OpenPhone MCP</strong></li>
                    <li>URL: <code style="background:#0b1220;color:var(--accent);padding:0.2rem 0.4rem;border-radius:6px;border:1px solid var(--border)">https://mcp.openphonelabs.com/sse</code></li>
                    <li>Complete OAuth flow and enter your OpenPhone API key</li>
                </ol>
                <div class="code" style="margin-top:0.9rem;">
                    <div class="code-header">Connector URL <button class="copy" data-copy-content="https://mcp.openphonelabs.com/sse">Copy</button></div>
                    <pre>https://mcp.openphonelabs.com/sse</pre>
                </div>
            </section>
        </section>



        <div class="footer">
            Powered by Cloudflare Workers • Compatible with Claude Desktop & ChatGPT
        </div>
    </main>

    <div class="toast" id="toast" role="status" aria-live="polite">Copied</div>

    <script>
        (function() {
            const prefersLight = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches;
            const saved = localStorage.getItem('theme');
            const theme = saved || (prefersLight ? 'light' : 'dark');
            if (theme === 'light') document.body.setAttribute('data-theme', 'light');
            const btn = document.getElementById('themeToggle');
            const setIcon = () => { btn.textContent = document.body.getAttribute('data-theme') === 'light' ? '🌚' : '🌙'; };
            btn.addEventListener('click', () => {
                const isLight = document.body.getAttribute('data-theme') === 'light';
                if (isLight) { document.body.removeAttribute('data-theme'); localStorage.setItem('theme', 'dark'); }
                else { document.body.setAttribute('data-theme', 'light'); localStorage.setItem('theme', 'light'); }
                setIcon();
            });
            setIcon();
        })();

        // Tabs
        (function() {
            const claudeBtn = document.getElementById('tab-claude-btn');
            const chatgptBtn = document.getElementById('tab-chatgpt-btn');
            const claudePanel = document.getElementById('tab-claude');
            const chatgptPanel = document.getElementById('tab-chatgpt');
            function select(tab) {
                const isClaude = tab === 'claude';
                claudeBtn.setAttribute('aria-selected', isClaude ? 'true' : 'false');
                chatgptBtn.setAttribute('aria-selected', isClaude ? 'false' : 'true');
                claudePanel.hidden = !isClaude;
                chatgptPanel.hidden = isClaude;
            }
            claudeBtn.addEventListener('click', () => select('claude'));
            chatgptBtn.addEventListener('click', () => select('chatgpt'));
        })();

        function showToast(text) {
            const el = document.getElementById('toast');
            el.textContent = text || 'Copied';
            el.classList.add('show');
            setTimeout(() => el.classList.remove('show'), 1600);
        }
        function copyText(text) {
            navigator.clipboard.writeText(text).then(() => showToast('Copied'));
        }

        // Copy buttons (target element text or provided content)
        document.querySelectorAll('.copy').forEach(btn => {
            btn.addEventListener('click', () => {
                const targetSel = btn.getAttribute('data-copy-target');
                const inline = btn.getAttribute('data-copy-content');
                if (inline) { copyText(inline); return; }
                if (!targetSel) return;
                const target = document.querySelector(targetSel);
                if (target) copyText(target.textContent || '');
            });
        });

        // CTA buttons
        document.getElementById('copyUrl').addEventListener('click', () => copyText('https://mcp.openphonelabs.com/sse'));
        document.getElementById('copyInspector').addEventListener('click', () => copyText('npx @modelcontextprotocol/inspector@latest'));

        // Keyboard focus ring
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Tab') document.body.classList.add('using-keyboard');
        });
        document.addEventListener('mousedown', () => document.body.classList.remove('using-keyboard'));
    </script>
</body>
</html>
  `;
}


function getAuthorizationPageHTML(clientId: string, redirectUri: string, scope: string, state: string | null, codeChallenge: string, codeChallengeMethod: string, error?: string): string {
	return `
<!DOCTYPE html>
<html>
<head>
    <title>Authorize OpenPhone Access</title>
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
            background: #1a1b2e;
            min-height: 100vh;
            color: #e2e8f0;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 2rem;
        }
        
        .auth-container {
            background: #2a2b3e;
            padding: 3rem;
            border-radius: 16px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06), 0 0 0 1px rgba(249, 115, 22, 0.1);
            border: 1px solid #374151;
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
            height: 3px;
            background: linear-gradient(90deg, #f97316 0%, #ea580c 50%, #dc2626 100%);
        }
        
        h1 {
            font-size: 2rem;
            font-weight: 700;
            color: #f8fafc;
            margin-bottom: 0.5rem;
            text-align: center;
        }
        
        .subtitle {
            color: #94a3b8;
            text-align: center;
            margin-bottom: 2rem;
            font-size: 1.1rem;
        }
        
        .scope-info {
            background: rgba(249, 115, 22, 0.05);
            border: 1px solid rgba(249, 115, 22, 0.2);
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1.5rem;
        }
        
        .scope-title {
            font-weight: 600;
            color: #f97316;
            margin-bottom: 0.5rem;
        }
        
        .scope-list {
            list-style: none;
            color: #d1d5db;
        }
        
        .scope-list li {
            margin: 0.25rem 0;
            padding-left: 1rem;
            position: relative;
        }
        
        .scope-list li::before {
            content: '✓';
            position: absolute;
            left: 0;
            color: #22c55e;
            font-weight: bold;
        }
        
        .form-group {
            margin-bottom: 1.5rem;
        }
        
        label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 600;
            color: #f8fafc;
        }
        
        input {
            width: 100%;
            padding: 0.875rem;
            border: 2px solid #4b5563;
            border-radius: 8px;
            font-size: 1rem;
            transition: border-color 0.2s ease;
            font-family: 'SF Mono', 'Monaco', monospace;
            background: #374151;
            color: #f8fafc;
        }
        
        input:focus {
            outline: none;
            border-color: #f97316;
            box-shadow: 0 0 0 3px rgba(249, 115, 22, 0.1);
        }
        
        .button-group {
            display: flex;
            gap: 1rem;
            margin-top: 2rem;
        }
        
        .btn {
            flex: 1;
            padding: 1rem;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s ease;
        }
        
        .btn-approve {
            background: #22c55e;
            color: white;
        }
        
        .btn-deny {
            background: #ef4444;
            color: white;
        }
        
        .btn:hover {
            transform: translateY(-2px);
        }
        
        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        
        .error {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: #f87171;
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 1.5rem;
            font-size: 0.9rem;
        }
        
        .help-text {
            font-size: 0.875rem;
            color: #94a3b8;
            margin-top: 0.5rem;
        }
        
        .client-info {
            background: rgba(156, 163, 175, 0.05);
            border: 1px solid rgba(156, 163, 175, 0.2);
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1.5rem;
            font-size: 0.9rem;
            color: #4b5563;
        }
    </style>
</head>
<body>
    <div class="auth-container">
        <h1>🔐 Authorize Access</h1>
        <p class="subtitle">Claude Desktop wants to access your OpenPhone account</p>
        
        <div class="client-info">
            <strong>Application:</strong> Claude Desktop<br>
            <strong>Redirect URI:</strong> ${redirectUri}
        </div>
        
        ${error ? `<div class="error">❌ ${error}</div>` : ''}
        
        <div class="scope-info">
            <div class="scope-title">Requested Permissions:</div>
            <ul class="scope-list">
                ${scope.includes('openphone:read') ? '<li>Read phone numbers and contacts</li>' : ''}
                ${scope.includes('openphone:write') ? '<li>Send messages and create contacts</li>' : ''}
                ${scope.includes('openphone:admin') ? '<li>Access call transcripts and admin functions</li>' : ''}
            </ul>
        </div>
        
        <form method="POST">
            <input type="hidden" name="client_id" value="${clientId}">
            <input type="hidden" name="redirect_uri" value="${redirectUri}">
            <input type="hidden" name="scope" value="${scope}">
            ${state ? `<input type="hidden" name="state" value="${state}">` : ''}
            <input type="hidden" name="code_challenge" value="${codeChallenge}">
            <input type="hidden" name="code_challenge_method" value="${codeChallengeMethod}">
            
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
                    Get your API key from your <a href="https://app.openphone.com" target="_blank" style="color: #8b5cf6; text-decoration: none;">OpenPhone dashboard</a> → Settings → Integrations → API
                </div>
            </div>
            
            <div class="button-group">
                <button type="submit" name="approved" value="false" class="btn btn-deny">
                    Deny Access
                </button>
                <button type="submit" name="approved" value="true" class="btn btn-approve">
                    Authorize Access
                </button>
            </div>
        </form>
    </div>
</body>
</html>
	`;
}

function getSuccessPageHTML(responseData: string, redirectUri?: string, state?: string | null): string {
	return `
<!DOCTYPE html>
<html>
<head>
    <title>Authorization Successful</title>
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
            background: #1a1b2e;
            min-height: 100vh;
            color: #e2e8f0;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 2rem;
        }
        
        .success-container {
            background: #2a2b3e;
            padding: 3rem;
            border-radius: 16px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06), 0 0 0 1px rgba(249, 115, 22, 0.1);
            border: 1px solid #374151;
            max-width: 500px;
            width: 100%;
            position: relative;
            overflow: hidden;
            text-align: center;
        }
        
        .success-container::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, #22c55e 0%, #16a34a 100%);
        }
        
        .success-icon {
            font-size: 4rem;
            margin-bottom: 1rem;
            animation: bounce 1s ease-in-out;
        }
        
        @keyframes bounce {
            0%, 20%, 50%, 80%, 100% { transform: translateY(0); }
            40% { transform: translateY(-10px); }
            60% { transform: translateY(-5px); }
        }
        
        h1 {
            font-size: 2rem;
            font-weight: 700;
            color: #22c55e;
            margin-bottom: 1rem;
        }
        
        .subtitle {
            color: #94a3b8;
            margin-bottom: 2rem;
            font-size: 1.1rem;
        }
        

    </style>
</head>
<body>
    <div class="success-container">
        <div class="success-icon">✅</div>
        <h1>Authorization Successful!</h1>
        <p class="subtitle">Your OpenPhone account has been connected to Claude Desktop.</p>
        <p style="margin: 1.5rem 0; color: #22c55e; font-weight: 600; font-size: 1.1rem;">
            🎉 You can now use OpenPhone tools in Claude!
        </p>
        
        <p style="color: #94a3b8; margin-bottom: 1rem;">
            You can safely close this tab and return to Claude Desktop.
        </p>
        
        <div id="countdown-container" style="margin: 1rem 0; padding: 1rem; background: rgba(249, 115, 22, 0.05); border: 1px solid rgba(249, 115, 22, 0.2); border-radius: 8px; display: none;">
            <p style="color: #f97316; font-weight: 600; margin-bottom: 0.5rem;">
                ⏱️ Auto-redirecting in <span id="countdown">3</span> seconds...
            </p>
            <button onclick="cancelRedirect()" style="background: #ef4444; color: white; border: none; padding: 0.5rem 1rem; border-radius: 8px; cursor: pointer; font-size: 0.9rem;">
                Cancel Auto-Redirect
            </button>
        </div>
        
        <div style="margin-top: 1rem; font-size: 0.9rem; color: #94a3b8;">
            <p>💡 Use <kbd style="background: #374151; color: #f8fafc; padding: 0.2rem 0.4rem; border-radius: 4px; font-family: monospace;">Ctrl+W</kbd> (or <kbd style="background: #374151; color: #f8fafc; padding: 0.2rem 0.4rem; border-radius: 4px; font-family: monospace;">Cmd+W</kbd> on Mac) to close this tab</p>
        </div>
    </div>

    <!-- Hidden response data for Claude Desktop -->
    <script type="application/json" id="oauth-response">${responseData}</script>

    <script>
        let hasUserInteracted = false;
        let autoRedirectTimer = null;
        let countdownTimer = null;
        let secondsLeft = 3;
        
        function cancelRedirect() {
            hasUserInteracted = true;
            if (autoRedirectTimer) {
                clearTimeout(autoRedirectTimer);
                autoRedirectTimer = null;
            }
            if (countdownTimer) {
                clearInterval(countdownTimer);
                countdownTimer = null;
            }
            document.getElementById('countdown-container').style.display = 'none';
        }
        
        function startCountdown() {
            const countdownContainer = document.getElementById('countdown-container');
            const countdownSpan = document.getElementById('countdown');
            
            countdownContainer.style.display = 'block';
            
            countdownTimer = setInterval(() => {
                secondsLeft--;
                countdownSpan.textContent = secondsLeft;
                
                if (secondsLeft <= 0) {
                    clearInterval(countdownTimer);
                }
            }, 1000);
        }
        
        // Add click listener to detect user interaction
        document.addEventListener('click', () => {
            if (!hasUserInteracted) {
                cancelRedirect();
            }
        });
        
        // Post message to opener immediately for OAuth flows
        setTimeout(() => {
            try {
                const responseData = document.getElementById('oauth-response').textContent;
                if (window.opener && responseData) {
                    window.opener.postMessage({
                        type: 'oauth_success',
                        data: JSON.parse(responseData)
                    }, '*');
                }
                
                // For Claude Desktop OAuth: handle redirect more gracefully
                const redirectUri = '${redirectUri || ''}';
                if (redirectUri && redirectUri !== 'urn:ietf:wg:oauth:2.0:oob' && responseData) {
                    const data = JSON.parse(responseData);
                    const callbackUrl = new URL(redirectUri);
                    callbackUrl.searchParams.set('code', data.code);
                    if (data.state) callbackUrl.searchParams.set('state', data.state);
                    
                    console.log('OAuth callback URL prepared:', callbackUrl.toString());
                    
                    // Auto-redirect for OAuth callbacks (including MCP inspector)
                    if (redirectUri && redirectUri !== 'urn:ietf:wg:oauth:2.0:oob') {
                        // Show countdown
                        startCountdown();
                        
                        autoRedirectTimer = setTimeout(() => {
                            if (!hasUserInteracted) {
                                try {
                                    console.log('Auto-redirecting to OAuth callback...');
                                    if (window.opener) {
                                        window.opener.location.href = callbackUrl.toString();
                                        window.close();
                                    } else if (window.parent && window.parent !== window) {
                                        window.parent.location.href = callbackUrl.toString();
                                    } else {
                                        window.location.href = callbackUrl.toString();
                                    }
                                } catch (e) {
                                    console.log('Auto-redirect failed:', e);
                                }
                            }
                        }, 3000);
                    }
                }
            } catch (e) {
                console.log('OAuth flow handling failed:', e);
            }
        }, 500);
    </script>
</body>
</html>
	`;
}
