# Query Tracking API

The OpenPhone MCP server now includes comprehensive query tracking functionality to monitor user interactions and tool usage.

## Features

- **Automatic Query Tracking**: All MCP tool calls are automatically tracked
- **User Identification**: Users are identified by hashed API keys for privacy
- **Client Detection**: Automatically detects Claude Desktop, ChatGPT, or other clients
- **Performance Metrics**: Tracks response times and success rates
- **Rich Metadata**: Includes user agent, timestamps, and error details

## API Endpoints

### Track a Query (Internal)
```
POST /tracking/track
Content-Type: application/json

{
  "userId": "hashed_api_key",
  "query": "Send message from +1234567890 to +0987654321: Hello!",
  "toolName": "send-message",
  "timestamp": 1704067200000,
  "responseTime": 1250,
  "success": true,
  "error": null,
  "metadata": {
    "userAgent": "Claude-User/1.0",
    "clientType": "claude"
  }
}
```

### Get Query History
```
GET /tracking/queries?limit=50&offset=0&userId=abc123&toolName=send-message&clientType=claude&startDate=1704067200000&endDate=1704153600000&success=true

Response:
{
  "queries": [
    {
      "id": "uuid",
      "userId": "hashed_api_key",
      "query": "Send message from +1234567890 to +0987654321: Hello!",
      "toolName": "send-message",
      "timestamp": 1704067200000,
      "responseTime": 1250,
      "success": true,
      "error": null,
      "metadata": {
        "userAgent": "Claude-User/1.0",
        "clientType": "claude"
      }
    }
  ],
  "total": 150,
  "hasMore": true
}
```

### Get Statistics
```
GET /tracking/stats

Response:
{
  "totalQueries": 1250,
  "uniqueUsers": 45,
  "queriesByTool": {
    "send-message": 800,
    "fetch-call-transcripts": 300,
    "fetch-messages": 150
  },
  "queriesByClient": {
    "claude": 1000,
    "chatgpt": 200,
    "other": 50
  },
  "averageResponseTime": 1200,
  "successRate": 0.95,
  "queriesByDay": {
    "2024-01-01": 50,
    "2024-01-02": 75,
    "2024-01-03": 100
  }
}
```

### Clear All Data
```
POST /tracking/clear

Response:
{
  "message": "Query tracking data cleared"
}
```

## Query Parameters

- `limit`: Number of queries to return (default: 50)
- `offset`: Number of queries to skip (default: 0)
- `userId`: Filter by specific user (hashed API key)
- `toolName`: Filter by specific tool name
- `clientType`: Filter by client type (claude, chatgpt, other)
- `startDate`: Filter queries after this timestamp
- `endDate`: Filter queries before this timestamp
- `success`: Filter by success status (true/false)

## Tracked Tools

Currently tracking the following MCP tools:
- `send-message`: Send SMS messages
- `fetch-call-transcripts`: Retrieve call transcripts
- `fetch-messages`: Get conversation messages
- `bulk-send-message`: Send messages to multiple recipients
- `create-contact`: Create new contacts
- `list-contacts`: Retrieve contact list
- `list-phone-numbers`: Get phone numbers
- `list-conversations`: Fetch conversations

## Privacy & Security

- **API Key Hashing**: User API keys are hashed using SHA-256 for identification
- **No Sensitive Data**: Message content and personal information are not stored
- **Automatic Cleanup**: Only the last 1000 queries are kept in memory
- **Client Detection**: User agent strings are stored for analytics

## Usage Examples

### Monitor Tool Usage
```bash
curl "https://mcp.openphonelabs.com/tracking/stats"
```

### Get Recent Queries
```bash
curl "https://mcp.openphonelabs.com/tracking/queries?limit=10"
```

### Filter by Client Type
```bash
curl "https://mcp.openphonelabs.com/tracking/queries?clientType=claude&limit=20"
```

### Get Failed Queries
```bash
curl "https://mcp.openphonelabs.com/tracking/queries?success=false&limit=50"
```

## Implementation Details

The query tracking system uses Cloudflare Durable Objects for persistent storage and is automatically integrated into all MCP tool handlers. No additional configuration is required - tracking begins immediately when the server starts.
