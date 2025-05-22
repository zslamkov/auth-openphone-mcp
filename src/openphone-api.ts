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
} 