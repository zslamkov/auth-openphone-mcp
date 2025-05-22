# Converting Existing OpenPhone MCP Server to Cloudflare Remote MCP

This guide shows how to adapt your existing local OpenPhone MCP server code to work with Cloudflare's remote MCP infrastructure.

## Current State
- ✅ Cloudflare remote MCP project created (using template)
- ✅ Existing `refere reference-index.ts` and `openphone-api.ts` files ready to port over functionality to `index.ts` and `openphone-api.ts` files.
- 🎯 Goal: Convert from local stdio transport to remote McpAgent with authentication

## Step 1: Update Your OpenPhone API Client

Replace the existing `src/openphone-api.ts` with your version, but make these adaptations for Cloudflare Workers:

```typescript
// src/openphone-api.ts
export class OpenPhoneClient {
  private apiKey: string;
  private baseUrl: string = 'https://api.openphone.com/v1';

  constructor(apiKey: string) {
    this.apiKey = apiKey;
  }

  private async request<T>(
    endpoint: string,
    method: 'GET' | 'POST' | 'PUT' | 'DELETE' = 'GET',
    body?: any
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    const headers = {
      'Authorization': this.apiKey,
      'Content-Type': 'application/json'
    };

    const options: RequestInit = {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined
    };

    // Use native fetch (available in Cloudflare Workers)
    const response = await fetch(url, options);

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`API request failed: ${response.status} ${errorText}`);
    }

    return response.json() as Promise<T>;
  }

  // Keep your existing methods exactly as they are
  async sendMessage(from: string, to: string[], content: string, userId: string): Promise<any> {
    return this.request<any>(
      '/messages',
      'POST',
      {
        from,
        to,
        content,
        userId
      }
    );
  }

  async createContact(contactData: any): Promise<any> {
    return this.request<any>(
      '/contacts',
      'POST',
      contactData
    );
  }
}
```

## Step 2: Convert Your MCP Server to McpAgent

Create a new file `src/openphone-mcp-agent.ts` that converts your existing MCP server logic:

```typescript
// src/openphone-mcp-agent.ts
import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { OpenPhoneClient } from "./openphone-api.js";

// Props from OAuth (user info + stored data)
type Props = {
  login: string;          // GitHub username from OAuth
}

// Environment bindings for Cloudflare
type Env = {
  OAUTH_PROVIDER: any;
  KV: KVNamespace;        // For storing user API keys
}

export class OpenPhoneMCPAgent extends McpAgent<Props, Env> {
  server = new McpServer({
    name: "OpenPhone",
    version: "1.0.0",
  });

  async init() {
    // Check if user has configured their OpenPhone API key
    const userApiKey = await this.getUserApiKey();
    
    if (!userApiKey) {
      // Only show setup tool if no API key configured
      this.addSetupTool();
      return;
    }

    // Add all your existing OpenPhone tools
    this.addOpenPhoneTools(userApiKey);
  }

  private async getUserApiKey(): Promise<string | null> {
    const key = `openphone_api_key:${this.props.login}`;
    return await this.env.KV.get(key);
  }

  private async saveUserApiKey(apiKey: string): Promise<void> {
    const key = `openphone_api_key:${this.props.login}`;
    await this.env.KV.put(key, apiKey);
  }

  private addSetupTool() {
    this.server.tool(
      "setup-api-key",
      {
        apiKey: z.string().describe("Your OpenPhone API key")
      },
      async ({ apiKey }) => {
        try {
          // Test the API key by making a simple request
          const testClient = new OpenPhoneClient(apiKey);
          // Add a simple test call here if OpenPhone has an endpoint for it
          
          await this.saveUserApiKey(apiKey);
          
          // Reinitialize with the new API key
          await this.addOpenPhoneTools(apiKey);
          
          return {
            content: [{
              type: "text",
              text: "✅ OpenPhone API key saved successfully! All OpenPhone tools are now available. Try asking me to send a message or create a contact."
            }]
          };
        } catch (error) {
          return {
            content: [{
              type: "text",
              text: `❌ Failed to save API key: ${error instanceof Error ? error.message : String(error)}`
            }],
            isError: true
          };
        }
      },
      {
        title: "Setup OpenPhone API Key",
        description: "Configure your OpenPhone API key to enable all tools"
      }
    );
  }

  private addOpenPhoneTools(apiKey: string) {
    const openPhoneClient = new OpenPhoneClient(apiKey);

    // Copy your exact tool definitions from index.ts, but update the implementation
    
    // Send Message Tool (adapted from your existing code)
    this.server.tool(
      "send-message",
      {
        from: z.string().describe("Your OpenPhone number (E.164 or ID) to send from"),
        to: z.string().describe("The recipient's phone number (E.164 format)"),
        content: z.string().describe("The message content")
      },
      async ({ from, to, content }: { from: string; to: string; content: string }) => {
        // Use the user's GitHub username as userId for now
        const userId = this.props.login;
        try {
          const result = await openPhoneClient.sendMessage(from, [to], content, userId);
          return {
            content: [{
              type: "text",
              text: `Message sent successfully to ${to}. Message ID: ${result.data?.id || result.id}`
            }]
          };
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : String(error);
          return {
            content: [{
              type: "text",
              text: `Error sending message: ${errorMessage}`
            }],
            isError: true
          };
        }
      },
      {
        title: "Send Text Message",
        openWorldHint: true,
        destructiveHint: false
      }
    );

    // Bulk Messages Tool (adapted from your existing code)
    this.server.tool(
      "bulk-messages",
      {
        from: z.string().describe("Your OpenPhone number (E.164 or ID) to send from"),
        to: z.array(z.string()).describe("Array of recipient phone numbers (E.164 format)"),
        content: z.string().describe("The message content")
      },
      async ({ from, to, content }: { from: string; to: string[]; content: string }) => {
        const userId = this.props.login;
        const results: { to: string; success: boolean; error?: string }[] = [];
        
        for (const number of to) {
          try {
            await openPhoneClient.sendMessage(from, [number], content, userId);
            results.push({ to: number, success: true });
          } catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            results.push({ to: number, success: false, error: errorMessage });
          }
        }
        
        const successCount = results.filter(r => r.success).length;
        const failCount = results.length - successCount;
        let summary = `Bulk message complete. Success: ${successCount}, Failed: ${failCount}.`;
        
        if (failCount > 0) {
          summary += '\nFailed numbers:';
          for (const r of results.filter(r => !r.success)) {
            summary += `\n${r.to}: ${r.error}`;
          }
        }
        
        return {
          content: [{
            type: "text",
            text: summary
          }]
        };
      },
      {
        title: "Send Bulk Messages",
        openWorldHint: true,
        destructiveHint: false
      }
    );

    // Create Contact Tool (adapted from your existing code)
    this.server.tool(
      "create-contact",
      {
        contacts: z.array(z.object({
          company: z.string(),
          emails: z.array(z.object({ 
            name: z.string(), 
            value: z.string().email() 
          })),
          firstName: z.string(),
          lastName: z.string(),
          phoneNumbers: z.array(z.object({ 
            name: z.string(), 
            value: z.string() 
          })),
          role: z.string()
        })).describe("Array of contacts to create. Each must include company, emails, firstName, lastName, phoneNumbers, and role.")
      },
      async ({ contacts }: { contacts: any[] }) => {
        const results: { contact: any; success: boolean; error?: string }[] = [];
        
        for (const contact of contacts) {
          try {
            await openPhoneClient.createContact({ defaultFields: contact });
            results.push({ contact, success: true });
          } catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            results.push({ contact, success: false, error: errorMessage });
          }
        }
        
        const successCount = results.filter(r => r.success).length;
        const failCount = results.length - successCount;
        let summary = `Create contact(s) complete. Success: ${successCount}, Failed: ${failCount}.`;
        
        if (failCount > 0) {
          summary += '\nFailed contacts:';
          for (const r of results.filter(r => !r.success)) {
            summary += `\n${r.contact.firstName} ${r.contact.lastName}: ${r.error}`;
          }
        }
        
        return {
          content: [{
            type: "text",
            text: summary
          }]
        };
      },
      {
        title: "Create Contact(s)",
        openWorldHint: true,
        destructiveHint: false
      }
    );
  }
}
```

## Step 3: Update the Main Index File

Replace the template's main MCP class reference in `src/index.ts` to use your OpenPhone agent:

```typescript
// src/index.ts
import OAuthProvider from "@cloudflare/workers-oauth-provider";
import { OpenPhoneMCPAgent } from "./openphone-mcp-agent.js";
import GitHubHandler from "./github-handler.js";

export default new OAuthProvider({
  apiRoute: "/sse",
  apiHandler: OpenPhoneMCPAgent.Router,
  defaultHandler: GitHubHandler,
  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/token",
  clientRegistrationEndpoint: "/register",
});
```

## Step 4: Update Package Dependencies

Make sure your `package.json` includes any dependencies from your original project:

```json
{
  "dependencies": {
    "@modelcontextprotocol/sdk": "^0.5.0",
    "zod": "^3.23.8",
    "@cloudflare/workers-oauth-provider": "latest",
    "agents": "latest"
  }
}
```

## Step 5: Set Up KV Namespace (if not already done)

```bash
# Create KV namespace for storing user API keys
wrangler kv:namespace create "KV"
wrangler kv:namespace create "KV" --preview

# Add the IDs to your wrangler.toml
```

Update `wrangler.toml`:

```toml
[[kv_namespaces]]
binding = "KV"
id = "your-kv-namespace-id"
preview_id = "your-preview-kv-namespace-id"
```

## Step 6: Test Local Development

```bash
# Start development server
npm run dev

# Test with MCP Inspector
npx @modelcontextprotocol/inspector@latest
# Connect to: http://localhost:8787/sse
```

## Step 7: Deploy and Test

```bash
# Deploy to Cloudflare
wrangler deploy

# Test the deployed version at:
# https://your-worker.workers.dev/sse
```

## Key Changes Summary

### What stays the same:
- ✅ All your tool definitions and logic
- ✅ OpenPhone API client methods
- ✅ Tool parameters and descriptions
- ✅ Error handling patterns

### What changes:
- 🔄 **Transport**: From stdio to HTTP/SSE via McpAgent
- 🔄 **Authentication**: Added GitHub OAuth flow
- 🔄 **API Key Management**: Stored per-user in KV instead of environment
- 🔄 **Initialization**: Conditional tool loading based on API key setup
- 🔄 **User Context**: Uses GitHub username instead of hardcoded userId

## User Experience Flow

1. **Connect**: User adds your server URL to their MCP client
2. **Authenticate**: GitHub OAuth flow
3. **Setup**: User sees only `setup-api-key` tool initially
4. **Configure**: User provides their OpenPhone API key
5. **Use**: All your existing OpenPhone tools become available

This approach preserves all your existing OpenPhone functionality while adding the benefits of remote access, user authentication, and secure API key management.