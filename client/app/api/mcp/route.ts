// app/api/mcp/route.ts - Proxy for MCP Server with SSE support
// Handles Streamable HTTP transport as used by MCP Inspector
import { NextRequest, NextResponse } from 'next/server';

// Store sessions in memory (in production, use Redis or similar)
const sessions = new Map<string, string>();

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const mcpUrl = request.headers.get('x-mcp-url');
    const mcpToken = request.headers.get('x-mcp-token');
    const sessionId = request.headers.get('x-session-id');

    console.log('=== MCP Proxy Request ===');
    console.log('URL:', mcpUrl);
    console.log('Session ID from client:', sessionId);
    console.log('Method:', body.method);
    console.log('Request ID:', body.id);

    if (!mcpUrl) {
      return NextResponse.json(
        { error: 'MCP URL is required' },
        { status: 400 }
      );
    }

    const headers: HeadersInit = {
      'Content-Type': 'application/json',
      'Accept': 'application/json, text/event-stream',  // Required for MCP SSE transport
    };

    if (mcpToken) {
      headers['Authorization'] = `Bearer ${mcpToken}`;
    }

    // Add session ID using the correct header name for Streamable HTTP transport
    // Note: On first request (initialize), there is no session ID yet
    if (sessionId) {
      headers['mcp-session-id'] = sessionId;  // Streamable HTTP format
      console.log('Sending mcp-session-id header:', sessionId);
    } else {
      console.log('No session ID - this should be the initialize request');
    }

    const response = await fetch(mcpUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });

    console.log('Response status:', response.status);
    const mcpSessionIdFromServer = response.headers.get('mcp-session-id');
    console.log('Server returned mcp-session-id:', mcpSessionIdFromServer);
    
    // Log error responses
    if (!response.ok) {
      console.log('⚠️  HTTP Error Status:', response.status, response.statusText);
      
      // Handle 401 Unauthorized - OAuth required
      if (response.status === 401) {
        const wwwAuth = response.headers.get('WWW-Authenticate');
        console.log('WWW-Authenticate header:', wwwAuth);
        
        // Return OAuth error to client
        return NextResponse.json(
          {
            error: {
              code: -32001,
              message: 'Authentication required',
              data: {
                www_authenticate: wwwAuth,
                requires_oauth: true
              }
            }
          },
          { status: 401 }
        );
      }
    }

    // Check if response is SSE stream
    const contentType = response.headers.get('content-type');
    
    if (contentType?.includes('text/event-stream')) {
      // Handle SSE stream
      const reader = response.body?.getReader();
      const decoder = new TextDecoder();
      let result = '';
      
      if (reader) {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          
          const chunk = decoder.decode(value, { stream: true });
          const lines = chunk.split('\n');
          
          for (const line of lines) {
            if (line.startsWith('data: ')) {
              const data = line.slice(6);
              if (data === '[DONE]') continue;
              
              try {
                const parsed = JSON.parse(data);
                // For MCP, we typically want the last complete message
                result = data;
              } catch (e) {
                // Skip malformed JSON
              }
            }
          }
        }
      }
      
      // Return the last complete JSON-RPC message with session info
      const jsonResponse = JSON.parse(result || '{}');
      const responseHeaders = new Headers();
      
      // Pass session ID back if present - check both header formats
      const responseSessionId = response.headers.get('mcp-session-id') || response.headers.get('x-session-id');
      if (responseSessionId) {
        responseHeaders.set('x-session-id', responseSessionId);
      }
      
      // Preserve the HTTP status code from the server
      return NextResponse.json(jsonResponse, { 
        status: response.status,
        headers: responseHeaders 
      });
    }

    // Handle regular JSON response
    const data = await response.json();
    const responseHeaders = new Headers();
    
    // Pass session ID back if present - check both header formats
    const responseSessionId = response.headers.get('mcp-session-id') || response.headers.get('x-session-id');
    if (responseSessionId) {
      responseHeaders.set('x-session-id', responseSessionId);
    }
    
    // Preserve the HTTP status code from the server
    return NextResponse.json(data, { 
      status: response.status,
      headers: responseHeaders 
    });
  } catch (error: any) {
    console.error('MCP Proxy Error:', error);
    console.error('Error stack:', error?.stack);
    console.error('Error message:', error?.message);
    return NextResponse.json(
      { 
        error: `Proxy error: ${error?.message || error}`,
        details: error?.stack,
        type: error?.constructor?.name
      },
      { status: 500 }
    );
  }
}
