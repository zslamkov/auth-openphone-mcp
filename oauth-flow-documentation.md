# OAuth 2.1 + PKCE Flow Documentation
## OpenPhone MCP Server Authentication Architecture

## Table of Contents
1. [Overview](#overview)
2. [Initial OAuth Flow](#initial-oauth-flow)
3. [Return Visit Flow](#return-visit-flow)
4. [Session Management](#session-management)
5. [Endpoints Reference](#endpoints-reference)
6. [Security Architecture](#security-architecture)

---

## Overview

The OpenPhone MCP server implements OAuth 2.1 with PKCE (Proof Key for Code Exchange) to securely authenticate users without exposing API keys in URLs or logs. The system uses stateless JWT-style tokens that embed encrypted API keys with HMAC-SHA256 signatures.

### Key Characteristics
- **Stateless tokens**: No server-side session storage required
- **1-hour token expiration**: Requires re-authentication after expiry
- **Auto-recreating OAuth client**: Survives Cloudflare Worker restarts
- **PKCE mandatory**: Prevents authorization code interception
- **API key validation**: Real-time validation against OpenPhone API

---

## Initial OAuth Flow

### Flow Diagram
```
Claude Desktop                    MCP Server                    OpenPhone API
     │                                │                              │
     ├──1. Discovery Request─────────>│                              │
     │   GET /.well-known/oauth-      │                              │
     │   authorization-server/sse      │                              │
     │                                │                              │
     │<──OAuth Metadata───────────────┤                              │
     │                                │                              │
     ├──2. Client Registration────────>│                              │
     │   POST /register               │                              │
     │                                │                              │
     │<──Client Credentials───────────┤                              │
     │   client_id: "openphone-       │                              │
     │   mcp-client"                  │                              │
     │                                │                              │
     ├──3. Authorization Request──────>│                              │
     │   GET /authorize?              │                              │
     │   client_id=...&               │                              │
     │   code_challenge=...           │                              │
     │                                │                              │
     │<──Consent Form HTML────────────┤                              │
     │                                │                              │
     │   [User enters API key]        │                              │
     │                                │                              │
     ├──4. Submit API Key──────────────>│                              │
     │   POST /authorize              │                              │
     │   api_key=...                  ├──Validate API Key──────────>│
     │                                │                              │
     │                                │<──Validation Response────────┤
     │                                │                              │
     │<──Authorization Code───────────┤                              │
     │   (Stateless, signed)          │                              │
     │                                │                              │
     ├──5. Token Exchange──────────────>│                              │
     │   POST /token                  │                              │
     │   code=...&                    │                              │
     │   code_verifier=...            │                              │
     │                                │                              │
     │<──Access Token─────────────────┤                              │
     │   (1-hour expiry)              │                              │
     │                                │                              │
     ├──6. MCP Request─────────────────>│                              │
     │   POST /sse                    │                              │
     │   Authorization: Bearer token   │                              │
     │                                │                              │
     │<──MCP Response──────────────────┤                              │
     │                                │                              │
```

### Detailed Steps

#### Step 1: OAuth Discovery
- **Endpoint**: `GET /.well-known/oauth-authorization-server/sse`
- **Handler**: `handleOAuthWellKnown()` (src/index.ts:151-181)
- **Response**: OAuth 2.1 metadata including authorization, token, and registration endpoints
- **Code Reference**: src/index.ts:622-626

#### Step 2: Dynamic Client Registration
- **Endpoint**: `POST /register`
- **Handler**: `handleOAuthRegister()` (src/index.ts:183-241)
- **Client ID**: Hardcoded as `"openphone-mcp-client"` (src/index.ts:192)
- **Response**: Client credentials (client_id, client_secret, redirect_uris)
- **Code Reference**: src/index.ts:647-651

#### Step 3: Authorization Request
- **Endpoint**: `GET /authorize`
- **Parameters**:
  - `client_id`: Must match registered client
  - `redirect_uri`: Callback URL for Claude/ChatGPT
  - `code_challenge`: PKCE challenge (Base64-URL encoded SHA256 hash)
  - `code_challenge_method`: Must be "S256"
  - `state`: CSRF protection token
- **Response**: HTML consent form
- **Code Reference**: src/index.ts:296-305

#### Step 4: API Key Submission & Validation
- **Endpoint**: `POST /authorize`
- **Form Data**: `api_key`, `approved`
- **Validation Process**:
  1. Check API key format (16-128 chars, alphanumeric) (src/index.ts:335-346)
  2. Validate against OpenPhone API (src/index.ts:349-355)
  3. Generate stateless authorization code (src/index.ts:391-403)
- **Authorization Code Structure**:
  ```typescript
  {
    code: string,
    client_id: string,
    redirect_uri: string,
    scope: string,
    code_challenge: string,
    code_challenge_method: "S256",
    expires_at: timestamp, // 10 minutes
    api_key: string // Embedded!
  }
  ```
- **Code Reference**: src/index.ts:308-425

#### Step 5: Token Exchange with PKCE Verification
- **Endpoint**: `POST /token`
- **Parameters**:
  - `grant_type`: Must be "authorization_code"
  - `code`: Authorization code from Step 4
  - `code_verifier`: PKCE verifier (plain text)
  - `redirect_uri`: Must match authorization request
  - `client_id`: Optional for PKCE flows
- **PKCE Verification**: `sha256(code_verifier) === code_challenge` (src/index.ts:492)
- **Response**: Access token (1-hour expiry)
- **Token Structure**:
  ```typescript
  {
    api_key: string,
    scope: string,
    exp: unix_timestamp,
    iat: unix_timestamp,
    sig: string // HMAC-SHA256 signature
  }
  ```
- **Code Reference**: src/index.ts:430-562

#### Step 6: Protected Resource Access
- **Endpoint**: `POST /sse`
- **Header**: `Authorization: Bearer [access_token]`
- **Authentication**: `authGate()` function (src/index.ts:564-601)
- **Process**:
  1. Extract bearer token (src/index.ts:569-581)
  2. Validate token signature (src/index.ts:585)
  3. Check expiration (src/index.ts:141-143)
  4. Extract API key from token (src/index.ts:600)
  5. Pass to MCP agent via header (src/index.ts:732)
- **Code Reference**: src/index.ts:673-751

---

## Return Visit Flow

### Scenario: User Returns After 3 Days

#### Problem: Token Expired
- Access tokens expire after 1 hour (src/index.ts:538)
- No refresh tokens implemented
- Must complete full OAuth flow again

#### Flow Sequence
```
1. Initial Request with Expired Token
   └─> 401 Unauthorized (src/index.ts:586-597)

2. Claude Desktop Detects 401
   └─> Initiates OAuth flow

3. Discovery (possibly cached)
   └─> GET /.well-known/oauth-authorization-server/sse

4. Client Auto-Recreation
   └─> Client recreated with same ID (src/index.ts:267-286)

5. Authorization (user re-enters API key)
   └─> GET /authorize → POST /authorize

6. Token Exchange
   └─> POST /token → New 1-hour token
```

### Auto-Recreation Mechanism
```typescript
// src/index.ts:267-286
let client = clients.get(clientId);
if (!client) {
  // Auto-register so the flow survives new isolates
  client = {
    client_id: clientId, // Always "openphone-mcp-client"
    client_secret: 'not-needed-for-pkce',
    redirect_uris: [redirectUri],
    scope: scope,
    created_at: Date.now()
  };
  clients.set(clientId, client);
}
```

---

## Session Management

### Current State: No Persistent Sessions
- **Token Storage**: Client-side only (Claude Desktop's responsibility)
- **Server State**: None (stateless architecture)
- **Worker Memory**: Cleared every ~5-10 minutes of inactivity
- **Durable Objects**: Used for MCP protocol, NOT OAuth state

### Token Lifecycle
```
Token Created (Hour 0)
    │
    ├─> Valid for 1 hour
    │
Token Expires (Hour 1)
    │
    ├─> 401 Unauthorized on next request
    │
    └─> Must re-authenticate
```

### API Key Flow Through System
```
1. User Input (HTML form)
       ↓
2. OAuth Authorization Code (embedded, signed)
       ↓
3. Access Token (embedded, signed)
       ↓
4. authGate() extraction
       ↓
5. X-OpenPhone-API-Key header
       ↓
6. MCP Agent usage
       ↓
7. OpenPhone API calls
```

---

## Endpoints Reference

### Public Endpoints (No Auth Required)

| Endpoint | Method | Purpose | Handler |
|----------|--------|---------|---------|
| `/` | GET | Homepage with setup instructions | src/index.ts:780-788 |
| `/.well-known/oauth-authorization-server/sse` | GET | OAuth discovery metadata | src/index.ts:151-181 |
| `/.well-known/oauth-protected-resource/sse` | GET | Protected resource metadata | src/index.ts:629-645 |
| `/register` | POST | Dynamic client registration | src/index.ts:183-241 |
| `/authorize` | GET | Show consent form | src/index.ts:296-305 |
| `/authorize` | POST | Process API key submission | src/index.ts:308-425 |
| `/token` | POST | Exchange code for token | src/index.ts:430-562 |

### Protected Endpoints (Bearer Token Required)

| Endpoint | Method | Purpose | Authentication |
|----------|--------|---------|---------------|
| `/sse` | POST | MCP protocol over SSE | authGate() → Bearer token |
| `/mcp` | POST | Alternative MCP endpoint | authGate() → Bearer token |

---

## Security Architecture

### Stateless Token Implementation

#### Token Creation (src/index.ts:95-122)
```typescript
async function createStatelessAccessToken(api_key, scope, env, expires_in = 3600) {
  const tokenData = {
    api_key,
    scope,
    exp: Math.floor(Date.now() / 1000) + expires_in,
    iat: Math.floor(Date.now() / 1000)
  };

  const signature = await sha256(secretKey + JSON.stringify(tokenData));
  const payload = { ...tokenData, sig: signature };

  return btoa(JSON.stringify(payload))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}
```

#### Token Validation (src/index.ts:124-149)
```typescript
async function validateStatelessAccessToken(token, env) {
  const payload = JSON.parse(atob(token));
  const { sig, ...tokenData } = payload;
  const expectedSignature = await sha256(secretKey + JSON.stringify(tokenData));

  if (sig !== expectedSignature) return null;
  if (tokenData.exp < now) return null;

  return { api_key: tokenData.api_key, scope: tokenData.scope };
}
```

### PKCE Protection
- **Challenge Generation**: Client creates random verifier, sends SHA256 hash
- **Verification**: Server validates `sha256(verifier) === challenge`
- **Purpose**: Prevents authorization code interception
- **Implementation**: src/index.ts:491-506

### Security Headers
```typescript
// src/index.ts:299-304
'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' fonts.googleapis.com; font-src fonts.gstatic.com"
'X-Frame-Options': 'DENY'
'X-Content-Type-Options': 'nosniff'
'Referrer-Policy': 'strict-origin-when-cross-origin'
```

---

## Production URL Configuration

- **Production Domain**: `https://mcp.openphonelabs.com`
- **Cloudflare Routes**: `mcp.openphonelabs.com/*` (wrangler.jsonc:11-13)
- **Durable Object Binding**: `OpenPhoneMCPAgent` → `MCP_OBJECT`

---

## Key Code References

| Component | Location | Line Numbers |
|-----------|----------|--------------|
| OAuth Client Definition | src/index.ts | 6-12 |
| Client Storage (in-memory) | src/index.ts | 32 |
| Secret Key Management | src/index.ts | 46-50 |
| Stateless Code Creation | src/index.ts | 52-67 |
| Stateless Code Validation | src/index.ts | 69-93 |
| Access Token Creation | src/index.ts | 95-122 |
| Access Token Validation | src/index.ts | 124-149 |
| OAuth Well-Known Handler | src/index.ts | 151-181 |
| Client Registration Handler | src/index.ts | 183-241 |
| Authorization Handler | src/index.ts | 243-428 |
| Token Exchange Handler | src/index.ts | 430-562 |
| Authentication Gate | src/index.ts | 564-601 |
| Main Worker Entry | src/index.ts | 604-790 |
| MCP Agent API Key Retrieval | src/openphone-mcp-agent.ts | 72-115 |