interface SendMessageRequest {
  from: string;
  to: string[];
  content: string;
}

interface ListConversationsParams {
  phoneNumber?: string;
  maxResults?: number;
}

interface ListCallsParams {
  phoneNumberId: string;
  participants: string[];
  userId?: string;
  maxResults?: number;
  pageToken?: string;
  createdAfter?: string;
  createdBefore?: string;
}

interface ApiError {
  status: number;
  message: string;
}

export class OpenPhoneClient {
  private apiKey: string;
  private baseUrl: string = 'https://api.openphone.com/v1';
  private defaultMaxResults = 10;

  constructor(apiKey: string) {
    if (!apiKey?.trim()) {
      throw new Error('API key is required');
    }
    this.apiKey = apiKey;
  }

  async validateApiKey(): Promise<boolean> {
    try {
      const response = await fetch(`${this.baseUrl}/phone-numbers`, {
        headers: {
          'Authorization': this.apiKey,
          'Content-Type': 'application/json'
        }
      });
      return response.ok;
    } catch {
      return false;
    }
  }

  private buildQueryString(params: Record<string, any>): string {
    const searchParams = new URLSearchParams();
    
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        if (Array.isArray(value)) {
          value.forEach(item => searchParams.append(key, String(item)));
        } else {
          searchParams.append(key, String(value));
        }
      }
    });
    
    return searchParams.toString();
  }

  private async request<T>(
    endpoint: string,
    method: 'GET' | 'POST' | 'PUT' | 'DELETE' = 'GET',
    body?: unknown
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

    try {
      const response = await fetch(url, options);

      if (!response.ok) {
        const errorText = await response.text();
        const error: ApiError = {
          status: response.status,
          message: errorText
        };
        throw new Error(`OpenPhone API Error (${error.status}): ${error.message}`);
      }

      return response.json() as Promise<T>;
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(`Unexpected error: ${String(error)}`);
    }
  }

  async sendMessage(from: string, to: string[], content: string): Promise<unknown> {
    if (!from?.trim() || !to?.length || !content?.trim()) {
      throw new Error('from, to, and content are required');
    }
    
    const payload: SendMessageRequest = { from, to, content };
    return this.request('/messages', 'POST', payload);
  }

  async createContact(contactData: Record<string, unknown>): Promise<unknown> {
    if (!contactData || Object.keys(contactData).length === 0) {
      throw new Error('Contact data is required');
    }
    
    return this.request('/contacts', 'POST', contactData);
  }

  async listPhoneNumbers(userId?: string): Promise<unknown> {
    const queryString = this.buildQueryString({ userId });
    const endpoint = queryString ? `/phone-numbers?${queryString}` : '/phone-numbers';
    return this.request(endpoint);
  }

  async listConversations(params: ListConversationsParams = {}): Promise<unknown> {
    const queryParams = {
      ...params,
      maxResults: params.maxResults ?? this.defaultMaxResults
    };
    
    const queryString = this.buildQueryString(queryParams);
    return this.request(`/conversations?${queryString}`);
  }

  async listCalls(params: ListCallsParams): Promise<unknown> {
    if (!params.phoneNumberId?.trim() || !params.participants?.length) {
      throw new Error('phoneNumberId and participants are required');
    }
    
    const queryParams = {
      ...params,
      maxResults: params.maxResults ?? this.defaultMaxResults
    };
    
    const queryString = this.buildQueryString(queryParams);
    return this.request(`/calls?${queryString}`);
  }

  async getCallTranscript(callId: string): Promise<unknown> {
    if (!callId?.trim()) {
      throw new Error('Call ID is required');
    }
    
    return this.request(`/call-transcripts/${callId}`);
  }
} 