// Query tracking types and interfaces
export interface QueryTrack {
  id: string;
  userId: string;           // User identifier (could be API key hash, client ID, etc.)
  query: string;           // The actual query/message from the user
  toolName?: string;       // Which MCP tool was called
  timestamp: number;       // Unix timestamp when query was made
  responseTime?: number;   // Response time in milliseconds
  success: boolean;        // Whether the query was successful
  error?: string;          // Error message if failed
  metadata?: {             // Additional metadata
    userAgent?: string;
    ipAddress?: string;
    clientType?: 'claude' | 'chatgpt' | 'other';
    [key: string]: any;
  };
}

export interface QueryStats {
  totalQueries: number;
  uniqueUsers: number;
  queriesByTool: Record<string, number>;
  queriesByClient: Record<string, number>;
  averageResponseTime: number;
  successRate: number;
  queriesByDay: Record<string, number>;
}

export interface QueryFilters {
  userId?: string;
  toolName?: string;
  clientType?: string;
  startDate?: number;
  endDate?: number;
  success?: boolean;
  limit?: number;
  offset?: number;
}
