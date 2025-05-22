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
      async ({ apiKey }: { apiKey: string }) => {
        try {
          // Test the API key by making a simple request
          const testClient = new OpenPhoneClient(apiKey);
          // Note: Add a simple test call here if OpenPhone has an endpoint for it
          // For now, we'll assume it's valid if it's provided
          
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
      }
    );
  }

  private addOpenPhoneTools(apiKey: string) {
    const openPhoneClient = new OpenPhoneClient(apiKey);

    // Send Message Tool
    this.server.tool(
      "send-message",
      {
        from: z.string().describe("Your OpenPhone number (E.164 or ID) to send from"),
        to: z.string().describe("The recipient's phone number (E.164 format)"),
        content: z.string().describe("The message content")
      },
      async ({ from, to, content }: { from: string; to: string; content: string }) => {
        // Use the user's GitHub username as userId
        const userId = this.props.login as string;
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
      }
    );

    // Bulk Messages Tool
    this.server.tool(
      "bulk-messages",
      {
        from: z.string().describe("Your OpenPhone number (E.164 or ID) to send from"),
        to: z.array(z.string()).describe("Array of recipient phone numbers (E.164 format)"),
        content: z.string().describe("The message content")
      },
      async ({ from, to, content }: { from: string; to: string[]; content: string }) => {
        const userId = this.props.login as string;
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
      }
    );

    // Create Contact Tool
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
      }
    );
  }
}