// app/api/mcp/route.ts - Proxy for MCP Server with SSE support
import { NextRequest, NextResponse } from 'next/server';

// Store sessions in memory (in production, use Redis or similar)
const sessions = new Map<string, string>();

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const mcpUrl = request.headers.get('x-mcp-url');
    const mcpToken = request.headers.get('x-mcp-token');
    const sessionId = request.headers.get('x-session-id');

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

    // Add session ID to request if available
    if (sessionId) {
      headers['X-Session-ID'] = sessionId;
    }

    const response = await fetch(mcpUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });

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
      
      // Pass session ID back if present
      const responseSessionId = response.headers.get('x-session-id');
      if (responseSessionId) {
        responseHeaders.set('x-session-id', responseSessionId);
      }
      
      return NextResponse.json(jsonResponse, { headers: responseHeaders });
    }

    // Handle regular JSON response
    const data = await response.json();
    const responseHeaders = new Headers();
    
    // Pass session ID back if present
    const responseSessionId = response.headers.get('x-session-id');
    if (responseSessionId) {
      responseHeaders.set('x-session-id', responseSessionId);
    }
    
    return NextResponse.json(data, { headers: responseHeaders });
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
