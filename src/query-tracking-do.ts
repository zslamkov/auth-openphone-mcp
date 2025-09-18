import { DurableObject } from "cloudflare:workers";
import { QueryTrack, QueryStats, QueryFilters } from "./query-tracking.js";

export class QueryTrackingDO extends DurableObject {
  private queries: QueryTrack[] = [];

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      switch (path) {
        case '/tracking/track':
          if (request.method === 'POST') {
            return await this.trackQuery(request);
          }
          break;

        case '/tracking/queries':
          if (request.method === 'GET') {
            return await this.getQueries(request);
          }
          break;

        case '/tracking/stats':
          if (request.method === 'GET') {
            return await this.getStats(request);
          }
          break;

        case '/tracking/clear':
          if (request.method === 'POST') {
            return await this.clearQueries(request);
          }
          break;

        default:
          return new Response('Not Found', { status: 404 });
      }
    } catch (error) {
      console.error('QueryTrackingDO error:', error);
      return new Response('Internal Server Error', { status: 500 });
    }

    return new Response('Method Not Allowed', { status: 405 });
  }

  private async trackQuery(request: Request): Promise<Response> {
    try {
      const queryTrack: Omit<QueryTrack, 'id'> = await request.json();
      
      // Generate unique ID
      const id = crypto.randomUUID();
      
      // Create complete query track record
      const track: QueryTrack = {
        id,
        ...queryTrack,
        timestamp: Date.now(),
      };

      // Store the query
      this.queries.push(track);

      // Keep only last 1000 queries to prevent memory issues
      if (this.queries.length > 1000) {
        this.queries = this.queries.slice(-1000);
      }

      console.log(`📊 Tracked query: ${track.toolName || 'unknown'} by user ${track.userId}`);

      return new Response(JSON.stringify({ id: track.id }), {
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      console.error('Error tracking query:', error);
      return new Response('Invalid JSON', { status: 400 });
    }
  }

  private async getQueries(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const filters: QueryFilters = {
      limit: parseInt(url.searchParams.get('limit') || '50'),
      offset: parseInt(url.searchParams.get('offset') || '0'),
    };

    if (url.searchParams.get('userId')) {
      filters.userId = url.searchParams.get('userId')!;
    }
    if (url.searchParams.get('toolName')) {
      filters.toolName = url.searchParams.get('toolName')!;
    }
    if (url.searchParams.get('clientType')) {
      filters.clientType = url.searchParams.get('clientType')!;
    }
    if (url.searchParams.get('startDate')) {
      filters.startDate = parseInt(url.searchParams.get('startDate')!);
    }
    if (url.searchParams.get('endDate')) {
      filters.endDate = parseInt(url.searchParams.get('endDate')!);
    }
    if (url.searchParams.get('success') !== null) {
      filters.success = url.searchParams.get('success') === 'true';
    }

    // Apply filters
    let filteredQueries = this.queries;

    if (filters.userId) {
      filteredQueries = filteredQueries.filter(q => q.userId === filters.userId);
    }
    if (filters.toolName) {
      filteredQueries = filteredQueries.filter(q => q.toolName === filters.toolName);
    }
    if (filters.clientType) {
      filteredQueries = filteredQueries.filter(q => q.metadata?.clientType === filters.clientType);
    }
    if (filters.startDate) {
      filteredQueries = filteredQueries.filter(q => q.timestamp >= filters.startDate!);
    }
    if (filters.endDate) {
      filteredQueries = filteredQueries.filter(q => q.timestamp <= filters.endDate!);
    }
    if (filters.success !== undefined) {
      filteredQueries = filteredQueries.filter(q => q.success === filters.success);
    }

    // Sort by timestamp (newest first)
    filteredQueries.sort((a, b) => b.timestamp - a.timestamp);

    // Apply pagination
    const start = filters.offset || 0;
    const end = start + (filters.limit || 50);
    const paginatedQueries = filteredQueries.slice(start, end);

    return new Response(JSON.stringify({
      queries: paginatedQueries,
      total: filteredQueries.length,
      hasMore: end < filteredQueries.length
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  private async getStats(request: Request): Promise<Response> {
    const stats: QueryStats = {
      totalQueries: this.queries.length,
      uniqueUsers: new Set(this.queries.map(q => q.userId)).size,
      queriesByTool: {},
      queriesByClient: {},
      averageResponseTime: 0,
      successRate: 0,
      queriesByDay: {}
    };

    // Calculate stats
    let totalResponseTime = 0;
    let successfulQueries = 0;

    for (const query of this.queries) {
      // Tool stats
      if (query.toolName) {
        stats.queriesByTool[query.toolName] = (stats.queriesByTool[query.toolName] || 0) + 1;
      }

      // Client type stats
      const clientType = query.metadata?.clientType || 'unknown';
      stats.queriesByClient[clientType] = (stats.queriesByClient[clientType] || 0) + 1;

      // Response time
      if (query.responseTime) {
        totalResponseTime += query.responseTime;
      }

      // Success rate
      if (query.success) {
        successfulQueries++;
      }

      // Daily stats
      const day = new Date(query.timestamp).toISOString().split('T')[0];
      stats.queriesByDay[day] = (stats.queriesByDay[day] || 0) + 1;
    }

    // Calculate averages
    if (this.queries.length > 0) {
      stats.averageResponseTime = totalResponseTime / this.queries.length;
      stats.successRate = successfulQueries / this.queries.length;
    }

    return new Response(JSON.stringify(stats), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  private async clearQueries(request: Request): Promise<Response> {
    this.queries = [];
    console.log('🗑️ Cleared all query tracking data');
    
    return new Response(JSON.stringify({ message: 'Query tracking data cleared' }), {
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
