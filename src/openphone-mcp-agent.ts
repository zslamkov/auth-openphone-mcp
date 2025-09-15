import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { OpenPhoneClient } from "./openphone-api.js";

// Props that can be passed from URL parameters or headers
type Props = {
  apiKey?: string;        // API key from URL parameter
  key?: string;           // Alternative short parameter name
  token?: string;         // Alternative token parameter name
  'x-openphone-api-key'?: string;  // API key from header
  'authorization'?: string;        // Bearer token format
}

// Environment bindings for Cloudflare
type Env = {
  OPENPHONE_API_KEY?: string;
  OAUTH_SECRET_KEY?: string;
  OPENAI_API_KEY?: string;
}

export class OpenPhoneMCPAgent extends McpAgent<Props, Env> {
  server = new McpServer({
    name: "OpenPhone",
    version: "1.0.0",
  });

  constructor(...args: any[]) {
    // Ensure base class initialization
    // @ts-ignore - pass through any constructor args required by the base class
    super(...args);
  }

  async init() {
    // Debug: Log all available props and env
    console.log('MCP Agent Init - Props:', JSON.stringify(this.props, null, 2));
    console.log('MCP Agent Init - Env keys:', Object.keys(this.env || {}));

    // Detect ChatGPT client
    const uaInit = (this.props as any)['user-agent']?.toLowerCase?.() || '';
    const isOpenAIMcpClientInit = uaInit.includes('openai-mcp');
    // Gate tool registration by client
    if (isOpenAIMcpClientInit) {
      console.log('🔧 ChatGPT client detected: registering limited legacy tools (send-message, fetch-call-transcripts)');
      this.addChatGPTLimitedTools();
    } else {
      console.log('🔧 Non-ChatGPT client detected: registering full OpenPhone tools');
      this.addOpenPhoneTools();
    }

    // Check for API key from multiple sources
    const apiKey = await this.getApiKey();

    if (!apiKey) {
      console.log('No API key found - tools will perform runtime API key checks');
      return;
    }

    console.log('API key found, validating...');

    // Validate the API key
    const isValid = await this.validateApiKey(apiKey);
    if (!isValid) {
      console.log('API key validation failed - handlers will continue to enforce at runtime');
      return;
    }

    console.log('API key valid');

    // Tools already registered; nothing else to add here
  }

  private async getApiKey(): Promise<string | null> {
    // Priority order:
    // 1. Environment variable (OPENPHONE_API_KEY from Cloudflare env)
    // 2. Authorization header (Bearer token)
    // 3. X-OpenPhone-API-Key header  
    // 4. URL parameters (apiKey, key, token)
    
    const props = this.props as Props;
    
    // Check environment variable first (most secure for production)
    const envKey = (this.env as Env).OPENPHONE_API_KEY;
    if (envKey) {
      console.log('Using API key from environment variable');
      return this.validateApiKeyFormat(envKey);
    }
    
    // Skip Authorization header - now handled by stateless tokens in auth gate
    // The API key is extracted from the token and passed via x-openphone-api-key header
    
    // Check custom header
    if (props['x-openphone-api-key']) {
      console.log('Using API key from X-OpenPhone-API-Key header');
      return this.validateApiKeyFormat(props['x-openphone-api-key']);
    }
    
    // Check URL parameters (multiple parameter names supported)
    if (props.apiKey) {
      console.log('Using API key from apiKey URL parameter');
      return this.validateApiKeyFormat(props.apiKey);
    }
    
    if (props.key) {
      console.log('Using API key from key URL parameter');
      return this.validateApiKeyFormat(props.key);
    }
    
    if (props.token) {
      console.log('Using API key from token URL parameter');
      return this.validateApiKeyFormat(props.token);
    }
    
    console.log('No API key found in any source');
    return null;
  }

  private validateApiKeyFormat(apiKey: string): string | null {
    if (!apiKey?.trim()) {
      return null;
    }
    
    // Basic format validation - adjust regex based on actual OpenPhone API key format
    const trimmedKey = apiKey.trim();
    
    // Validate length (typical API keys are 32-64 characters)
    if (trimmedKey.length < 16 || trimmedKey.length > 128) {
      console.warn('API key length validation failed');
      return null;
    }
    
    // Validate characters (alphanumeric and common special chars)
    if (!/^[a-zA-Z0-9._-]+$/.test(trimmedKey)) {
      console.warn('API key contains invalid characters');
      return null;
    }
    
    return trimmedKey;
  }

  private async validateApiKey(apiKey: string): Promise<boolean> {
    try {
      const testClient = new OpenPhoneClient(apiKey);
      return await testClient.validateApiKey();
    } catch {
      return false;
    }
  }

  // --- AI middleware planner (OpenAI) ---
  private async planSearchWithOpenAI(query: string): Promise<{
    actions: Array<{
      type: 'messages' | 'calls';
      inboxPhoneNumber?: string;          // E.164 preferred
      participantPhoneNumber?: string;    // E.164 preferred
      maxResults?: number;
      createdAfter?: string;              // ISO 8601
      createdBefore?: string;             // ISO 8601
      keywords?: string;                  // optional text filter
    }>;
  } | null> {
    // AI middleware removed
    return null;
  }

  private addChatGPTTools() {
    console.log('🔧 Adding search tool...');
    // ChatGPT MCP Search Tool
  }

  private addOpenPhoneTools() {

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
          const apiKey = await this.getApiKey();
          if (!apiKey || !(await this.validateApiKey(apiKey))) {
            return { content: [{ type: 'text', text: 'API key required or invalid' }], isError: true };
          }
          const openPhoneClient = new OpenPhoneClient(apiKey);
          const result = await openPhoneClient.sendMessage(from, [to], content) as any;
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
        const apiKey = await this.getApiKey();
        if (!apiKey || !(await this.validateApiKey(apiKey))) {
          return { content: [{ type: 'text', text: 'API key required or invalid' }], isError: true };
        }
        const openPhoneClient = new OpenPhoneClient(apiKey);
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
        const apiKey = await this.getApiKey();
        if (!apiKey || !(await this.validateApiKey(apiKey))) {
          return { content: [{ type: 'text', text: 'API key required or invalid' }], isError: true };
        }
        const openPhoneClient = new OpenPhoneClient(apiKey);
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

    // Fetch Call Transcripts Tool
    this.server.tool(
      "fetch-call-transcripts",
      {
        inboxPhoneNumber: z.string().describe("Your OpenPhone inbox number (E.164 format like +15555555555) to find transcripts for"),
        participantPhoneNumber: z.string().optional().describe("Optional: specific participant phone number to filter conversations (E.164 format)"),
        maxResults: z.number().optional().default(10).describe("Maximum number of calls to fetch transcripts for (default: 10)"),
        createdAfter: z.string().optional().describe("Optional: filter calls created after this date (ISO 8601 format like 2024-01-01T00:00:00Z)"),
        createdBefore: z.string().optional().describe("Optional: filter calls created before this date (ISO 8601 format)")
      },
      async ({ inboxPhoneNumber, participantPhoneNumber, maxResults = 10, createdAfter, createdBefore }: { 
        inboxPhoneNumber: string; 
        participantPhoneNumber?: string;
        maxResults?: number;
        createdAfter?: string;
        createdBefore?: string;
      }) => {
        try {
          const apiKey = await this.getApiKey();
          if (!apiKey || !(await this.validateApiKey(apiKey))) {
            return { content: [{ type: 'text', text: 'API key required or invalid' }], isError: true };
          }
          const openPhoneClient = new OpenPhoneClient(apiKey);
          // Step 1: List phone numbers to find phoneNumberId
          const phoneNumbersResponse = await openPhoneClient.listPhoneNumbers() as any;
          
          // Find the matching phone number
          const phoneNumberData = phoneNumbersResponse.data?.find((pn: any) => 
            pn.number === inboxPhoneNumber || 
            pn.id === inboxPhoneNumber
          );
          
          if (!phoneNumberData) {
            return {
              content: [{
                type: "text",
                text: `Error: Could not find phone number ${inboxPhoneNumber} in your OpenPhone workspace. Available numbers: ${phoneNumbersResponse.data?.map((pn: any) => pn.number).join(', ') || 'none'}`
              }],
              isError: true
            };
          }

          const phoneNumberId = phoneNumberData.id;
          const userId = phoneNumberData.users?.[0]?.id;
          
          // Step 2: List conversations to get participants if not provided
          let participantsToSearch: string[] = [];
          
          if (participantPhoneNumber) {
            participantsToSearch = [participantPhoneNumber];
          } else {
            // Get conversations to find participants
            const conversationsResponse = await openPhoneClient.listConversations({
              phoneNumber: phoneNumberId,
              maxResults: 50
            }) as any;
            
            // Extract unique participants from conversations
            const participants = new Set<string>();
            conversationsResponse.data?.forEach((conv: any) => {
              conv.participants?.forEach((participantPhoneNumber: string) => {
                if (participantPhoneNumber) {
                  // More permissive filtering - just make sure it's not the same number
                  const participantNum = participantPhoneNumber;
                  const inboxNum = inboxPhoneNumber;
                  
                  // Check if they're different (handle various formats)
                  const normalizedParticipant = participantNum.replace(/[^\d]/g, '');
                  const normalizedInbox = inboxNum.replace(/[^\d]/g, '');
                  
                  if (normalizedParticipant !== normalizedInbox && participantNum !== phoneNumberData.number) {
                    participants.add(participantNum);
                  }
                }
              });
            });
            
            participantsToSearch = Array.from(participants);
          }

          if (participantsToSearch.length === 0) {
            return {
              content: [{
                type: "text",
                text: `No conversations found for ${inboxPhoneNumber}. Make sure the number has call history.`
              }],
              isError: true
            };
          }

          // Step 3: Get calls and transcripts for each participant
          const allTranscripts: any[] = [];
          let totalCallsChecked = 0;
          
          for (const participant of participantsToSearch) {
            if (allTranscripts.length >= maxResults) break;
            
            try {
              // List calls with this participant
              const callsResponse = await openPhoneClient.listCalls({
                phoneNumberId,
                participants: [participant],
                userId,
                maxResults: Math.min(maxResults - allTranscripts.length, 20),
                createdAfter,
                createdBefore
              }) as any;
              
              // Step 4: Get transcripts for each call
              if (callsResponse.data && callsResponse.data.length > 0) {
                for (const call of callsResponse.data) {
                  if (allTranscripts.length >= maxResults) break;
                  totalCallsChecked++;
                  
                  try {
                    const transcriptResponse = await openPhoneClient.getCallTranscript(call.id) as any;
                    
                    if (transcriptResponse.data && transcriptResponse.data.status === 'completed' && transcriptResponse.data.dialogue) {
                      allTranscripts.push({
                        callId: call.id,
                        participant: participant,
                        direction: call.direction,
                        startedAt: call.startedAt,
                        answeredAt: call.answeredAt,
                        endedAt: call.endedAt,
                        duration: call.duration,
                        transcript: transcriptResponse.data
                      });
                    }
                  } catch (transcriptError) {
                    // Transcript not available for this call, skip silently
                    console.warn(`No transcript available for call ${call.id}`);
                  }
                }
              }
            } catch (callsError) {
              console.warn(`Error fetching calls for participant ${participant}:`, callsError);
            }
          }

          if (allTranscripts.length === 0) {
            return {
              content: [{
                type: "text",
                text: `No call transcripts found for ${inboxPhoneNumber}. Checked ${totalCallsChecked} calls. Transcripts are only available on OpenPhone Business plan and for calls where transcription was enabled.`
              }]
            };
          }

          // Format the response
          const summary = `Found ${allTranscripts.length} call transcripts for ${inboxPhoneNumber} (checked ${totalCallsChecked} calls):\n\n`;
          
          let formattedTranscripts = "";
          allTranscripts.forEach((transcript, index) => {
            formattedTranscripts += `## Call ${index + 1}\n`;
            formattedTranscripts += `**Call ID:** ${transcript.callId}\n`;
            formattedTranscripts += `**Participant:** ${transcript.participant}\n`;
            formattedTranscripts += `**Direction:** ${transcript.direction}\n`;
            formattedTranscripts += `**Started:** ${transcript.startedAt}\n`;
            formattedTranscripts += `**Duration:** ${Math.round(transcript.duration || 0)}s\n`;
            formattedTranscripts += `**Transcript Duration:** ${Math.round(transcript.transcript.duration || 0)}s\n\n`;
            
            if (transcript.transcript.dialogue && transcript.transcript.dialogue.length > 0) {
              formattedTranscripts += `**Transcript:**\n`;
              transcript.transcript.dialogue.forEach((segment: any) => {
                const speaker = segment.userId ? `User ${segment.userId}` : segment.identifier;
                const timestamp = `[${Math.round(segment.start)}s]`;
                formattedTranscripts += `${timestamp} **${speaker}:** ${segment.content}\n`;
              });
            } else {
              formattedTranscripts += `**Transcript:** No dialogue available\n`;
            }
            
            formattedTranscripts += `\n---\n\n`;
          });

          return {
            content: [{
              type: "text",
              text: summary + formattedTranscripts
            }]
          };
          
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : String(error);
          return {
            content: [{
              type: "text",
              text: `Error fetching call transcripts: ${errorMessage}`
            }],
            isError: true
          };
        }
      }
    );

    // Fetch Messages Tool
    this.registerFetchMessagesTool();
 
 
  }
 
  // Shared registration for fetch-messages (reused by ChatGPT-limited and full toolsets)
  private registerFetchMessagesTool() {
    this.server.tool(
      "fetch-messages",
      {
        inboxPhoneNumber: z.string().describe("Your OpenPhone inbox number (E.164 format like +15555555555) to fetch messages for"),
        participantPhoneNumber: z.string().optional().describe("Optional: specific participant phone number to filter conversations (E.164 format)"),
        maxResults: z.number().optional().default(10).describe("Maximum number of messages to fetch (default: 10, max: 100)"),
        createdAfter: z.string().optional().describe("Optional: filter messages created after this date (ISO 8601 format like 2024-01-01T00:00:00Z)"),
        createdBefore: z.string().optional().describe("Optional: filter messages created before this date (ISO 8601 format)"),
        userId: z.string().optional().describe("Optional: filter messages by specific user ID (US123abc format)")
      },
      async ({ inboxPhoneNumber, participantPhoneNumber, maxResults = 10, createdAfter, createdBefore, userId }: { 
        inboxPhoneNumber: string; 
        participantPhoneNumber?: string;
        maxResults?: number;
        createdAfter?: string;
        createdBefore?: string;
        userId?: string;
      }) => {
        try {
          const apiKey = await this.getApiKey();
          if (!apiKey || !(await this.validateApiKey(apiKey))) {
            return { content: [{ type: 'text', text: 'API key required or invalid' }], isError: true };
          }
          const openPhoneClient = new OpenPhoneClient(apiKey);
          const phoneNumbersResponse = await openPhoneClient.listPhoneNumbers() as any;
          const phoneNumberData = phoneNumbersResponse.data?.find((pn: any) => 
            pn.number === inboxPhoneNumber || 
            pn.id === inboxPhoneNumber
          );
          if (!phoneNumberData) {
            return {
              content: [{ type: 'text', text: `Error: Could not find phone number ${inboxPhoneNumber} in your OpenPhone workspace. Available numbers: ${phoneNumbersResponse.data?.map((pn: any) => pn.number).join(', ') || 'none'}` }],
              isError: true
            };
          }
          const phoneNumberId = phoneNumberData.id;
          
          let participantsToSearch: string[] = [];
          if (participantPhoneNumber) {
            participantsToSearch = [participantPhoneNumber];
          } else {
            const conversationsResponse = await openPhoneClient.listConversations({ phoneNumber: phoneNumberId, maxResults: 50 }) as any;
            const participants = new Set<string>();
            conversationsResponse.data?.forEach((conv: any) => {
              conv.participants?.forEach((participantPhoneNumber: string) => {
                if (participantPhoneNumber) {
                  const participantNum = participantPhoneNumber;
                  const inboxNum = inboxPhoneNumber;
                  const normalizedParticipant = participantNum.replace(/[^\d]/g, '');
                  const normalizedInbox = inboxNum.replace(/[^\d]/g, '');
                  if (normalizedParticipant !== normalizedInbox && participantNum !== phoneNumberData.number) {
                    participants.add(participantNum);
                  }
                }
              });
            });
            participantsToSearch = Array.from(participants);
          }
          if (participantsToSearch.length === 0) {
            return { content: [{ type: 'text', text: `No conversations found for ${inboxPhoneNumber}. Make sure the number has message history.` }], isError: true };
          }
          const allMessages: any[] = [];
          let totalParticipantsChecked = 0;
          for (const participant of participantsToSearch) {
            if (allMessages.length >= maxResults) break;
            totalParticipantsChecked++;
            try {
              const messagesResponse = await openPhoneClient.listMessages({
                phoneNumberId,
                participants: [participant],
                userId,
                maxResults: Math.min(maxResults - allMessages.length, 100),
                createdAfter,
                createdBefore
              }) as any;
              if (messagesResponse.data && messagesResponse.data.length > 0) {
                messagesResponse.data.forEach((message: any) => {
                  if (allMessages.length < maxResults) {
                    allMessages.push({
                      messageId: message.id,
                      participant: participant,
                      direction: message.direction,
                      from: message.from,
                      to: message.to,
                      text: message.text,
                      status: message.status,
                      userId: message.userId,
                      createdAt: message.createdAt,
                      updatedAt: message.updatedAt
                    });
                  }
                });
              }
            } catch (messagesError) {
              console.warn(`Error fetching messages for participant ${participant}:`, messagesError);
            }
          }
          if (allMessages.length === 0) {
            return { content: [{ type: 'text', text: `No messages found for ${inboxPhoneNumber}. Checked ${totalParticipantsChecked} participants.` }] };
          }
          allMessages.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
          const summary = `Found ${allMessages.length} messages for ${inboxPhoneNumber} (checked ${totalParticipantsChecked} participants):\n\n`;
          let formattedMessages = "";
          allMessages.forEach((message, index) => {
            formattedMessages += `## Message ${index + 1}\n`;
            formattedMessages += `**Message ID:** ${message.messageId}\n`;
            formattedMessages += `**Participant:** ${message.participant}\n`;
            formattedMessages += `**Direction:** ${message.direction}\n`;
            formattedMessages += `**From:** ${message.from}\n`;
            formattedMessages += `**To:** ${message.to.join(', ')}\n`;
            formattedMessages += `**Status:** ${message.status}\n`;
            formattedMessages += `**Created:** ${message.createdAt}\n`;
            if (message.userId) {
              formattedMessages += `**User ID:** ${message.userId}\n`;
            }
            formattedMessages += `**Message:** ${message.text}\n`;
            formattedMessages += `\n---\n\n`;
          });
          return { content: [{ type: 'text', text: summary + formattedMessages }] };
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : String(error);
          return { content: [{ type: 'text', text: `Error fetching messages: ${errorMessage}` }], isError: true };
        }
      }
    );
  }

  private addChatGPTLimitedTools() {
    // Send Message Tool (runtime API key check)
    this.server.tool(
      "send-message",
      {
        from: z.string().describe("Your OpenPhone number (E.164 or ID) to send from"),
        to: z.string().describe("The recipient's phone number (E.164 format)"),
        content: z.string().describe("The message content")
      },
      async ({ from, to, content }: { from: string; to: string; content: string }) => {
        try {
          const apiKey = await this.getApiKey();
          if (!apiKey || !(await this.validateApiKey(apiKey))) {
            return { content: [{ type: 'text', text: 'API key required or invalid' }], isError: true };
          }
          const openPhoneClient = new OpenPhoneClient(apiKey);
          const result = await openPhoneClient.sendMessage(from, [to], content) as any;
          return {
            content: [{ type: 'text', text: `Message sent successfully to ${to}. Message ID: ${result.data?.id || result.id}` }]
          };
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : String(error);
          return { content: [{ type: 'text', text: `Error sending message: ${errorMessage}` }], isError: true };
        }
      }
    );

    // Fetch Call Transcripts Tool (runtime API key check)
    this.server.tool(
      "fetch-call-transcripts",
      {
        inboxPhoneNumber: z.string().describe("Your OpenPhone inbox number (E.164 format like +15555555555) to find transcripts for"),
        participantPhoneNumber: z.string().optional().describe("Optional: specific participant phone number to filter conversations (E.164 format)"),
        maxResults: z.number().optional().default(10).describe("Maximum number of calls to fetch transcripts for (default: 10)"),
        createdAfter: z.string().optional().describe("Optional: filter calls created after this date (ISO 8601 format like 2024-01-01T00:00:00Z)"),
        createdBefore: z.string().optional().describe("Optional: filter calls created before this date (ISO 8601 format)")
      },
      async ({ inboxPhoneNumber, participantPhoneNumber, maxResults = 10, createdAfter, createdBefore }: { 
        inboxPhoneNumber: string; 
        participantPhoneNumber?: string;
        maxResults?: number;
        createdAfter?: string;
        createdBefore?: string;
      }) => {
        try {
          const apiKey = await this.getApiKey();
          if (!apiKey || !(await this.validateApiKey(apiKey))) {
            return { content: [{ type: 'text', text: 'API key required or invalid' }], isError: true };
          }
          const openPhoneClient = new OpenPhoneClient(apiKey);
          const phoneNumbersResponse = await openPhoneClient.listPhoneNumbers() as any;
          const phoneNumberData = phoneNumbersResponse.data?.find((pn: any) => pn.number === inboxPhoneNumber || pn.id === inboxPhoneNumber);
          if (!phoneNumberData) {
            return { content: [{ type: 'text', text: `Could not find phone number ${inboxPhoneNumber}` }], isError: true };
          }
          const phoneNumberId = phoneNumberData.id;
          const userId = phoneNumberData.users?.[0]?.id;
          let participantsToSearch: string[] = [];
          if (participantPhoneNumber) {
            participantsToSearch = [participantPhoneNumber];
          } else {
            const conversationsResponse = await openPhoneClient.listConversations({ phoneNumber: phoneNumberId, maxResults: 50 }) as any;
            const participants = new Set<string>();
            conversationsResponse.data?.forEach((conv: any) => conv.participants?.forEach((p: string) => { if (p) participants.add(p); }));
            participantsToSearch = Array.from(participants);
          }
          const allTranscripts: any[] = [];
          for (const participant of participantsToSearch) {
            if (allTranscripts.length >= maxResults) break;
            try {
              const callsResponse = await openPhoneClient.listCalls({ phoneNumberId, participants: [participant], userId, maxResults: Math.min(maxResults - allTranscripts.length, 20), createdAfter, createdBefore }) as any;
              if (callsResponse.data) {
                for (const call of callsResponse.data) {
                  if (allTranscripts.length >= maxResults) break;
                  try {
                    const transcriptResponse = await openPhoneClient.getCallTranscript(call.id) as any;
                    if (transcriptResponse.data && transcriptResponse.data.dialogue) {
                      allTranscripts.push({ callId: call.id, participant, direction: call.direction, startedAt: call.startedAt, duration: call.duration, transcript: transcriptResponse.data });
                    }
                  } catch {}
                }
              }
            } catch {}
          }
          if (allTranscripts.length === 0) {
            return { content: [{ type: 'text', text: `No call transcripts found for ${inboxPhoneNumber}.` }] };
          }
          const summary = `Found ${allTranscripts.length} call transcripts for ${inboxPhoneNumber}:\n\n`;
          let formatted = '';
          allTranscripts.forEach((t, i) => {
            formatted += `## Call ${i + 1}\n`;
            formatted += `**Call ID:** ${t.callId}\n`;
            formatted += `**Participant:** ${t.participant}\n`;
            formatted += `**Direction:** ${t.direction}\n`;
            formatted += `**Started:** ${t.startedAt}\n`;
            formatted += `**Duration:** ${Math.round(t.duration || 0)}s\n`;
            if (t.transcript?.dialogue?.length) {
              formatted += `**Transcript:**\n`;
              t.transcript.dialogue.forEach((seg: any) => { formatted += `[${Math.round(seg.start)}s] **${seg.userId ? 'User ' + seg.userId : seg.identifier}:** ${seg.content}\n`; });
            }
            formatted += `\n---\n\n`;
          });
          return { content: [{ type: 'text', text: summary + formatted }] };
        } catch (error) {
          const msg = error instanceof Error ? error.message : String(error);
          return { content: [{ type: 'text', text: `Error fetching call transcripts: ${msg}` }], isError: true };
        }
      }
    );

    // Reuse the same fetch-messages tool as in the full toolset
    this.registerFetchMessagesTool();
  }


}