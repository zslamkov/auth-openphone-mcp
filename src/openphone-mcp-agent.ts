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
      return await testClient.validateApiKey();
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
  }
}