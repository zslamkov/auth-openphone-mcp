import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { OpenPhoneClient } from "./openphone-api.js";

// Props that can be passed from URL parameters
type Props = {
  apiKey?: string;        // API key from URL parameter
}

// Environment bindings for Cloudflare
type Env = {
  OPENPHONE_API_KEY?: string;
}

export class OpenPhoneMCPAgent extends McpAgent<Props, Env> {
  server = new McpServer({
    name: "OpenPhone",
    version: "1.0.0",
  });

  async init() {
    // Check for API key from multiple sources
    const apiKey = await this.getApiKey();
    
    if (!apiKey) {
      // No API key provided - server will have no tools available
      return;
    }

    // Validate the API key
    const isValid = await this.validateApiKey(apiKey);
    if (!isValid) {
      // Invalid API key - server will have no tools available
      return;
    }

    // Add all OpenPhone tools
    this.addOpenPhoneTools(apiKey);
  }

  private async getApiKey(): Promise<string | null> {
    // Priority order:
    // 1. URL parameter (from Claude Desktop config)
    // 2. Environment variable (for server-wide config)
    
    // Check URL parameter first
    const propsApiKey = (this.props as Props).apiKey;
    if (propsApiKey) {
      return propsApiKey;
    }
    
    // Fallback to environment variable
    return (this.env as Env).OPENPHONE_API_KEY || null;
  }

  private async validateApiKey(apiKey: string): Promise<boolean> {
    try {
      const testClient = new OpenPhoneClient(apiKey);
      // Make a simple test call to validate the API key
      const response = await fetch('https://api.openphone.com/v1/phone-numbers', {
        headers: {
          'Authorization': apiKey,
          'Content-Type': 'application/json'
        }
      });
      return response.ok;
    } catch {
      return false;
    }
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
        try {
          const result = await openPhoneClient.sendMessage(from, [to], content);
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
        const results: { to: string; success: boolean; error?: string }[] = [];
        
        for (const number of to) {
          try {
            await openPhoneClient.sendMessage(from, [number], content);
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