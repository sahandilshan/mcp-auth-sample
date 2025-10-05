// app/api/oauth/discover/route.ts - OAuth discovery endpoint
import { NextRequest, NextResponse } from 'next/server';

/**
 * Server-side OAuth discovery to avoid CORS issues
 * Discovers the authorization server for a given MCP URL
 */
export async function POST(request: NextRequest) {
  try {
    const { mcpUrl } = await request.json();
    
    if (!mcpUrl) {
      return NextResponse.json(
        { error: 'MCP URL is required' },
        { status: 400 }
      );
    }
    
    console.log('🔍 Starting OAuth discovery for:', mcpUrl);
    
    const url = new URL(mcpUrl);
    const baseUrl = `${url.protocol}//${url.host}`;
    
    // Step 1: Try to access the protected resource
    try {
      console.log('Step 1: Trying to access protected resource...');
      const protectedResponse = await fetch(mcpUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 0,
          method: 'initialize',
          params: {
            protocolVersion: '2024-11-05',
            capabilities: {},
            clientInfo: { name: 'mcp-oauth-client', version: '1.0.0' }
          }
        })
      });
      
      console.log('Protected resource response status:', protectedResponse.status);
      
      if (protectedResponse.status === 401) {
        const wwwAuth = protectedResponse.headers.get('WWW-Authenticate');
        console.log('WWW-Authenticate header:', wwwAuth);
        
        if (wwwAuth) {
          // Parse WWW-Authenticate header to extract authorization server URL
          const realmMatch = wwwAuth.match(/realm="([^"]+)"/);
          if (realmMatch && realmMatch[1]) {
            const authServerUrl = realmMatch[1];
            console.log('Found auth server in WWW-Authenticate:', authServerUrl);
            
            // Try to fetch metadata from the realm URL
            const metadata = await tryFetchMetadata(authServerUrl);
            if (metadata) {
              return NextResponse.json(metadata);
            }
          }
        }
      }
    } catch (error) {
      console.log('Protected resource access failed:', error);
    }
    
    // Step 2: Try /.well-known/oauth-authorization-server
    console.log('Step 2: Trying /.well-known/oauth-authorization-server');
    let metadata = await tryFetchMetadata(`${baseUrl}/.well-known/oauth-authorization-server`);
    if (metadata) {
      return NextResponse.json(metadata);
    }
    
    // Try with resource path
    const resourcePath = url.pathname.split('/').slice(0, -1).join('/');
    if (resourcePath) {
      metadata = await tryFetchMetadata(`${baseUrl}${resourcePath}/.well-known/oauth-authorization-server`);
      if (metadata) {
        return NextResponse.json(metadata);
      }
    }
    
    // Step 3: Try /.well-known/openid-configuration
    console.log('Step 3: Trying /.well-known/openid-configuration');
    metadata = await tryFetchMetadata(`${baseUrl}/.well-known/openid-configuration`);
    if (metadata) {
      return NextResponse.json(metadata);
    }
    
    // Try with resource path
    if (resourcePath) {
      metadata = await tryFetchMetadata(`${baseUrl}${resourcePath}/.well-known/openid-configuration`);
      if (metadata) {
        return NextResponse.json(metadata);
      }
    }
    
    console.log('❌ No authorization server metadata found');
    return NextResponse.json(
      { error: 'No authorization server found' },
      { status: 404 }
    );
  } catch (error: any) {
    console.error('Discovery error:', error);
    return NextResponse.json(
      { error: `Discovery failed: ${error.message}` },
      { status: 500 }
    );
  }
}

/**
 * Try to fetch authorization server metadata from a URL
 */
async function tryFetchMetadata(url: string): Promise<any | null> {
  try {
    console.log('Trying:', url);
    const response = await fetch(url, {
      headers: {
        'Accept': 'application/json'
      }
    });
    
    if (response.ok) {
      const metadata = await response.json();
      
      // Validate that it has required OAuth endpoints
      if (metadata.authorization_endpoint && metadata.token_endpoint) {
        console.log('✅ Found valid metadata at:', url);
        return metadata;
      } else {
        console.log('❌ Invalid metadata (missing endpoints):', url);
      }
    } else {
      console.log('❌ Not found:', url, response.status);
    }
  } catch (error) {
    console.log('❌ Fetch failed:', url, error);
  }
  
  return null;
}
