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

  // Send Message
  async sendMessage(from: string, to: string[], content: string): Promise<any> {
    return this.request<any>(
      '/messages',
      'POST',
      {
        from,
        to,
        content
      }
    );
  }

  // Create Contact
  async createContact(contactData: any): Promise<any> {
    return this.request<any>(
      '/contacts',
      'POST',
      contactData
    );
  }

  // List Phone Numbers
  async listPhoneNumbers(userId?: string): Promise<any> {
    const params = new URLSearchParams();
    if (userId) {
      params.append('userId', userId);
    }
    
    const endpoint = params.toString() ? `/phone-numbers?${params.toString()}` : '/phone-numbers';
    return this.request<any>(endpoint);
  }

  // List Conversations
  async listConversations(params: {
    phoneNumber?: string;
    maxResults?: number;
  }): Promise<any> {
    const queryParams = new URLSearchParams();
    
    if (params.phoneNumber) {
      queryParams.append('phoneNumber', params.phoneNumber);
    }
    if (params.maxResults) {
      queryParams.append('maxResults', params.maxResults.toString());
    }
    
    // Default maxResults if not provided
    if (!params.maxResults) {
      queryParams.append('maxResults', '10');
    }
    
    const endpoint = `/conversations?${queryParams.toString()}`;
    return this.request<any>(endpoint);
  }

  // List Calls
  async listCalls(params: {
    phoneNumberId: string;
    participants: string[];
    userId?: string;
    maxResults?: number;
    pageToken?: string;
    createdAfter?: string;
    createdBefore?: string;
  }): Promise<any> {
    const queryParams = new URLSearchParams();
    
    queryParams.append('phoneNumberId', params.phoneNumberId);
    params.participants.forEach(participant => queryParams.append('participants', participant));
    
    if (params.userId) queryParams.append('userId', params.userId);
    if (params.maxResults) queryParams.append('maxResults', params.maxResults.toString());
    if (params.pageToken) queryParams.append('pageToken', params.pageToken);
    if (params.createdAfter) queryParams.append('createdAfter', params.createdAfter);
    if (params.createdBefore) queryParams.append('createdBefore', params.createdBefore);
    
    // Default maxResults if not provided
    if (!params.maxResults) {
      queryParams.append('maxResults', '10');
    }
    
    const endpoint = `/calls?${queryParams.toString()}`;
    return this.request<any>(endpoint);
  }

  // Get Call Transcript
  async getCallTranscript(callId: string): Promise<any> {
    return this.request<any>(`/call-transcripts/${callId}`);
  }
} 