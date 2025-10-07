// app/page.tsx - Main AI Agent Chat Interface
'use client';

import { useState, useRef, useEffect } from 'react';
import { ThemeToggle } from './components/theme-toggle';
import {
  generatePKCE,
  generateState,
  buildAuthorizationUrl,
  exchangeCodeForToken,
  storeOAuthState,
  retrieveOAuthState,
  clearOAuthState,
  storeTokens,
  retrieveTokens,
  clearTokens,
  type AuthorizationServerMetadata,
  type OAuthState,
} from './lib/oauth-utils';

interface Message {
  role: 'user' | 'assistant';
  content: string;
}

interface MCPTool {
  name: string;
  description: string;
  inputSchema: any;
}

export default function MCPAgent() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [mcpUrl, setMcpUrl] = useState('');
  const [mcpToken, setMcpToken] = useState('');
  const [sessionId, setSessionId] = useState('');
  const [tools, setTools] = useState<MCPTool[]>([]);
  const [connected, setConnected] = useState(false);
  const [loading, setLoading] = useState(false);
  
  // OAuth settings
  const [clientId, setClientId] = useState('');
  const [useOAuth, setUseOAuth] = useState(false);
  const [oauthMetadata, setOauthMetadata] = useState<AuthorizationServerMetadata | null>(null);
  const [oauthInProgress, setOauthInProgress] = useState(false);
  const oauthPopupRef = useRef<Window | null>(null);
  const popupCheckIntervalRef = useRef<NodeJS.Timeout | null>(null);
  
  // AI Model settings
  const [aiProvider, setAiProvider] = useState<'openai' | 'google' | 'azure'>('openai');
  const [apiKey, setApiKey] = useState('');
  const [modelName, setModelName] = useState('');
  
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  // Set default model when provider changes
  useEffect(() => {
    if (aiProvider === 'openai') {
      setModelName('gpt-4o-mini');
    } else if (aiProvider === 'google') {
      setModelName('gemini-2.0-flash-exp');
    } else if (aiProvider === 'azure') {
      setModelName('gpt-4');
    }
  }, [aiProvider]);

  // Handle OAuth callback
  useEffect(() => {
    const handleOAuthCallback = async (event: MessageEvent) => {
      // Only accept messages from our own origin
      if (event.origin !== window.location.origin) {
        return;
      }
      
      if (event.data.type === 'oauth_success') {
        console.log('OAuth callback received:', event.data);
        
        // Clear popup check interval
        if (popupCheckIntervalRef.current) {
          clearInterval(popupCheckIntervalRef.current);
          popupCheckIntervalRef.current = null;
        }
        
        const { code, state } = event.data;
        const savedState = retrieveOAuthState();
        
        if (!savedState) {
          alert('OAuth state not found. Please try again.');
          setOauthInProgress(false);
          return;
        }
        
        // Verify state parameter
        if (state !== savedState.state) {
          alert('OAuth state mismatch. Possible security issue.');
          clearOAuthState();
          setOauthInProgress(false);
          return;
        }
        
        // Exchange code for token
        try {
          setOauthInProgress(true);
          
          if (!oauthMetadata?.token_endpoint) {
            alert('Token endpoint not found');
            setOauthInProgress(false);
            return;
          }
          
          const tokens = await exchangeCodeForToken(
            oauthMetadata.token_endpoint,
            code,
            savedState.codeVerifier,
            savedState.clientId,
            savedState.redirectUri
          );
          
          // Store tokens
          storeTokens(savedState.mcpUrl, tokens);
          setMcpToken(tokens.access_token);
          clearOAuthState();
          
          alert('OAuth authentication successful! You can now connect.');
          setOauthInProgress(false);
        } catch (error: any) {
          alert(`Token exchange failed: ${error.message}`);
          clearOAuthState();
          setOauthInProgress(false);
        }
      } else if (event.data.type === 'oauth_error') {
        console.error('OAuth error:', event.data);
        
        // Clear popup check interval
        if (popupCheckIntervalRef.current) {
          clearInterval(popupCheckIntervalRef.current);
          popupCheckIntervalRef.current = null;
        }
        
        alert(`OAuth error: ${event.data.error_description || event.data.error}`);
        clearOAuthState();
        setOauthInProgress(false);
      }
    };
    
    window.addEventListener('message', handleOAuthCallback);
    return () => {
      window.removeEventListener('message', handleOAuthCallback);
      // Clean up interval on unmount
      if (popupCheckIntervalRef.current) {
        clearInterval(popupCheckIntervalRef.current);
      }
    };
  }, [oauthMetadata]);

  // Check for stored tokens on mount
  useEffect(() => {
    if (mcpUrl && useOAuth) {
      const tokens = retrieveTokens(mcpUrl);
      if (tokens) {
        setMcpToken(tokens.access_token);
        console.log('Loaded stored OAuth token');
      }
    }
  }, [mcpUrl, useOAuth]);

  // Discover OAuth authorization server (directly from browser)
  const discoverOAuth = async () => {
    if (!mcpUrl) {
      alert('Please enter MCP URL first');
      return;
    }
    
    try {
      setLoading(true);
      
      console.log('🔍 Starting OAuth discovery from browser...');
      
      // Import and use the client-side discovery function
      const { discoverAuthorizationServer } = await import('./lib/oauth-utils');
      const metadata = await discoverAuthorizationServer(mcpUrl);
      
      if (!metadata) {
        alert('No authorization server found.\n\nMake sure your MCP server:\n- Returns 401 with WWW-Authenticate header, or\n- Exposes /.well-known/oauth-authorization-server, or\n- Exposes /.well-known/openid-configuration');
        return;
      }
      
      setOauthMetadata(metadata);
      setUseOAuth(true);
      
      console.log('✅ OAuth metadata discovered:', metadata);
      alert(`Found authorization server!\n\nAuthorization endpoint:\n${metadata.authorization_endpoint}\n\nToken endpoint:\n${metadata.token_endpoint}`);
    } catch (error: any) {
      console.error('❌ Discovery error:', error);
      alert(`Discovery error: ${error.message}\n\nCheck browser console for details.`);
    } finally {
      setLoading(false);
    }
  };

  // Start OAuth flow
  const startOAuthFlow = async () => {
    if (!mcpUrl || !clientId) {
      alert('Please enter MCP URL and Client ID');
      return;
    }
    
    if (!oauthMetadata) {
      alert('Please discover OAuth server first');
      return;
    }
    
    try {
      setOauthInProgress(true);
      
      // Generate PKCE values
      const pkce = await generatePKCE();
      const state = generateState();
      const redirectUri = `${window.location.origin}/api/oauth/callback`;
      
      // Store OAuth state
      const oauthState: OAuthState = {
        state,
        codeVerifier: pkce.codeVerifier,
        redirectUri,
        mcpUrl,
        clientId,
      };
      storeOAuthState(oauthState);
      
      // Extract scopes from metadata (from RFC 8707 protected resource)
      const scopes = oauthMetadata.scopes_supported;
      const scopeString = scopes && scopes.length > 0 ? scopes.join(' ') : undefined;
      
      if (scopeString) {
        console.log('Using scopes from protected resource metadata:', scopeString);
      }
      
      // Build authorization URL
      const authUrl = buildAuthorizationUrl(
        oauthMetadata.authorization_endpoint,
        clientId,
        redirectUri,
        state,
        pkce.codeChallenge,
        pkce.codeChallengeMethod,
        scopeString
      );
      
      console.log('Opening authorization URL:', authUrl);
      
      // Open authorization URL in popup
      const width = 600;
      const height = 700;
      const left = window.screenX + (window.outerWidth - width) / 2;
      const top = window.screenY + (window.outerHeight - height) / 2;
      
      const popup = window.open(
        authUrl,
        'OAuth Authorization',
        `width=${width},height=${height},left=${left},top=${top}`
      );
      
      // Store popup reference
      oauthPopupRef.current = popup;
      
      // Check if popup was blocked
      if (!popup) {
        alert('Popup was blocked! Please allow popups for this site and try again.');
        setOauthInProgress(false);
        clearOAuthState();
        return;
      }
      
      // Monitor popup window - detect if user closes it manually
      popupCheckIntervalRef.current = setInterval(() => {
        if (popup.closed) {
          console.log('OAuth popup was closed by user');
          
          // Clear interval
          if (popupCheckIntervalRef.current) {
            clearInterval(popupCheckIntervalRef.current);
            popupCheckIntervalRef.current = null;
          }
          
          // Only show alert if OAuth is still in progress (not already completed)
          if (oauthInProgress) {
            alert('Authentication was cancelled. Please try again if you want to authenticate.');
            setOauthInProgress(false);
            clearOAuthState();
          }
        }
      }, 500); // Check every 500ms
      
    } catch (error: any) {
      alert(`OAuth flow error: ${error.message}`);
      setOauthInProgress(false);
      clearOAuthState();
    }
  };

  // Reset/Clear OAuth authentication
  const resetOAuthAuthentication = () => {
    // Close popup if still open
    if (oauthPopupRef.current && !oauthPopupRef.current.closed) {
      oauthPopupRef.current.close();
    }
    
    // Clear popup check interval
    if (popupCheckIntervalRef.current) {
      clearInterval(popupCheckIntervalRef.current);
      popupCheckIntervalRef.current = null;
    }
    
    // Clear all OAuth state and tokens
    clearOAuthState();
    if (mcpUrl) {
      clearTokens(mcpUrl);
    }
    
    // Reset OAuth UI state
    setOauthMetadata(null);
    setOauthInProgress(false);
    setMcpToken('');
    setUseOAuth(false);
    
    console.log('OAuth authentication reset');
    alert('OAuth authentication has been reset. You can start fresh.');
  };

  // Connect to MCP Server
  const connectMCP = async () => {
    try {
      setLoading(true);
      
      // Check if we need OAuth but don't have a token
      if (useOAuth && !mcpToken) {
        alert('Please authenticate with OAuth first');
        return;
      }
      
      // Step 1: Initialize session
      const initHeaders: any = {
        'Content-Type': 'application/json',
        'x-mcp-url': mcpUrl,
      };
      
      if (mcpToken) {
        initHeaders['x-mcp-token'] = mcpToken;
      }

      // Initialize MCP connection
      const initResponse = await fetch('/api/mcp', {
        method: 'POST',
        headers: initHeaders,
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 0,
          method: 'initialize',
          params: {
            protocolVersion: '2024-11-05',
            capabilities: {
              tools: {}
            },
            clientInfo: {
              name: 'mcp-ai-agent',
              version: '1.0.0'
            }
          }
        })
      });

      const initData = await initResponse.json();
      
      // Check for HTTP errors (like 401 Unauthorized)
      if (!initResponse.ok) {
        // Handle OAuth required
        if (initResponse.status === 401 && initData.error?.data?.requires_oauth) {
          alert('OAuth authentication required. Please click "Discover OAuth" and authenticate.');
          // Automatically discover OAuth
          await discoverOAuth();
          return;
        }
        
        const errorMsg = initData.error_description || initData.error || `HTTP ${initResponse.status}`;
        alert(`Connection failed: ${errorMsg}`);
        return;
      }
      
      // Check for JSON-RPC errors
      if (initData.error) {
        alert(`Initialization error: ${initData.error.message}`);
        return;
      }

      // Extract session ID from response headers - CRITICAL!
      const newSessionId = initResponse.headers.get('x-session-id');
      console.log('Received session ID from initialize:', newSessionId);
      
      if (newSessionId) {
        setSessionId(newSessionId);
      } else {
        console.error('WARNING: No session ID received from server!');
      }

      // Step 2: Send initialized notification
      const notifyHeaders: any = {
        'Content-Type': 'application/json',
        'x-mcp-url': mcpUrl,
      };
      
      if (mcpToken) {
        notifyHeaders['x-mcp-token'] = mcpToken;
      }
      
      // CRITICAL: Use the newSessionId variable, not state (state hasn't updated yet!)
      if (newSessionId) {
        notifyHeaders['x-session-id'] = newSessionId;
        console.log('Sending initialized with session ID:', newSessionId);
      }

      await fetch('/api/mcp', {
        method: 'POST',
        headers: notifyHeaders,
        body: JSON.stringify({
          jsonrpc: '2.0',
          method: 'notifications/initialized'
        })
      });

      // Step 3: List tools
      const toolsHeaders: any = {
        'Content-Type': 'application/json',
        'x-mcp-url': mcpUrl,
      };
      
      if (mcpToken) {
        toolsHeaders['x-mcp-token'] = mcpToken;
      }
      
      if (newSessionId) {
        toolsHeaders['x-session-id'] = newSessionId;
        console.log('Sending tools/list with session ID:', newSessionId);
      }

      const response = await fetch('/api/mcp', {
        method: 'POST',
        headers: toolsHeaders,
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/list',
          params: {}
        })
      });

      const data = await response.json();
      
      // Check for HTTP errors
      if (!response.ok) {
        const errorMsg = data.error_description || data.error || `HTTP ${response.status}`;
        alert(`Error listing tools: ${errorMsg}`);
        return;
      }
      
      // Check for JSON-RPC errors
      if (data.error) {
        alert(`Error: ${data.error.message}`);
        return;
      }

      setTools(data.result?.tools || []);
      setConnected(true);
      alert(`Connected! Found ${data.result?.tools?.length || 0} tools`);
    } catch (error) {
      alert(`Connection failed: ${error}`);
    } finally {
      setLoading(false);
    }
  };

  // Call MCP Tool
  const callMCPTool = async (toolName: string, args: any) => {
    const headers: any = {
      'Content-Type': 'application/json',
      'x-mcp-url': mcpUrl,
    };
    
    if (mcpToken) {
      headers['x-mcp-token'] = mcpToken;
    }
    
    if (sessionId) {
      headers['x-session-id'] = sessionId;
    }

    const response = await fetch('/api/mcp', {
      method: 'POST',
      headers,
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: Date.now(),
        method: 'tools/call',
        params: {
          name: toolName,
          arguments: args
        }
      })
    });

    const data = await response.json();
    return data.result;
  };

  // Send message to AI
  const sendMessage = async () => {
    if (!input.trim() || !apiKey) return;

    const userMessage: Message = { role: 'user', content: input };
    setMessages(prev => [...prev, userMessage]);
    setInput('');
    setLoading(true);

    try {
      // Prepare tools for AI
      const aiTools = tools.map(tool => ({
        type: 'function',
        function: {
          name: tool.name,
          description: tool.description,
          parameters: tool.inputSchema
        }
      }));

      let aiResponse;

      // Call appropriate AI model
      if (aiProvider === 'openai' || aiProvider === 'azure') {
        aiResponse = await callOpenAI(userMessage.content, aiTools);
      } else if (aiProvider === 'google') {
        aiResponse = await callGoogle(userMessage.content, aiTools);
      }

      if (aiResponse) {
        setMessages(prev => [...prev, { role: 'assistant', content: aiResponse }]);
      }
    } catch (error) {
      setMessages(prev => [...prev, { 
        role: 'assistant', 
        content: `Error: ${error}` 
      }]);
    } finally {
      setLoading(false);
    }
  };

  // OpenAI / Azure OpenAI
  const callOpenAI = async (message: string, tools: any[]) => {
    const endpoint = aiProvider === 'azure' 
      ? 'YOUR_AZURE_ENDPOINT/openai/deployments/YOUR_DEPLOYMENT/chat/completions?api-version=2024-02-15-preview'
      : 'https://api.openai.com/v1/chat/completions';

    const headers: any = {
      'Content-Type': 'application/json',
    };

    if (aiProvider === 'azure') {
      headers['api-key'] = apiKey;
    } else {
      headers['Authorization'] = `Bearer ${apiKey}`;
    }

    const response = await fetch(endpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        model: modelName || (aiProvider === 'azure' ? 'gpt-4' : 'gpt-4o-mini'),
        messages: [
          ...messages,
          { role: 'user', content: message }
        ],
        tools: tools.length > 0 ? tools : undefined,
        tool_choice: tools.length > 0 ? 'auto' : undefined
      })
    });

    const data = await response.json();
    const choice = data.choices[0];

    // Handle tool calls
    if (choice.message.tool_calls) {
      let finalResponse = '';
      let lastToolResult: any = null;
      
      for (const toolCall of choice.message.tool_calls) {
        const toolName = toolCall.function.name;
        const toolArgs = JSON.parse(toolCall.function.arguments);
        
        lastToolResult = await callMCPTool(toolName, toolArgs);
        finalResponse += `🔧 Used tool: ${toolName}\n`;
        finalResponse += `📊 Result: ${JSON.stringify(lastToolResult, null, 2)}\n\n`;
      }

      // Get final response from AI with tool results
      const finalAIResponse = await fetch(endpoint, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          model: modelName || (aiProvider === 'azure' ? 'gpt-4' : 'gpt-4o-mini'),
          messages: [
            ...messages,
            { role: 'user', content: message },
            choice.message,
            {
              role: 'function',
              name: choice.message.tool_calls[0].function.name,
              content: JSON.stringify(lastToolResult)
            }
          ]
        })
      });

      const finalData = await finalAIResponse.json();
      return finalResponse + finalData.choices[0].message.content;
    }

    return choice.message.content;
  };

  // Google Gemini
  const callGoogle = async (message: string, tools: any[]) => {
    const model = modelName || 'gemini-2.0-flash-exp';
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [
            ...messages.map(m => ({
              role: m.role === 'user' ? 'user' : 'model',
              parts: [{ text: m.content }]
            })),
            {
              role: 'user',
              parts: [{ text: message }]
            }
          ],
          tools: tools.length > 0 ? [{
            functionDeclarations: tools.map(t => ({
              name: t.function.name,
              description: t.function.description,
              parameters: t.function.parameters
            }))
          }] : undefined
        })
      }
    );

    const data = await response.json();
    const candidate = data.candidates[0];

    // Handle function calls
    if (candidate.content.parts[0].functionCall) {
      const functionCall = candidate.content.parts[0].functionCall;
      const toolResult = await callMCPTool(functionCall.name, functionCall.args);
      
      // Get final response
      const finalResponse = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            contents: [
              ...messages.map(m => ({
                role: m.role === 'user' ? 'user' : 'model',
                parts: [{ text: m.content }]
              })),
              { role: 'user', parts: [{ text: message }] },
              { role: 'model', parts: [{ functionCall }] },
              { 
                role: 'function',
                parts: [{
                  functionResponse: {
                    name: functionCall.name,
                    response: toolResult
                  }
                }]
              }
            ]
          })
        }
      );

      const finalData = await finalResponse.json();
      return `🔧 Used tool: ${functionCall.name}\n\n` + 
             finalData.candidates[0].content.parts[0].text;
    }

    return candidate.content.parts[0].text;
  };

  return (
    <div className="flex h-screen bg-gray-100 dark:bg-gray-900">
      {/* Sidebar */}
      <div className="w-80 bg-white dark:bg-gray-800 p-6 border-r border-gray-200 dark:border-gray-700 overflow-y-auto">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">🤖 MCP AI Agent</h1>
          <ThemeToggle />
        </div>
        
        {/* AI Provider Settings */}
        <div className="mb-6">
          <h3 className="font-semibold mb-2 text-gray-900 dark:text-white">AI Model</h3>
          <select 
            value={aiProvider} 
            onChange={(e) => setAiProvider(e.target.value as any)}
            className="w-full p-2 border border-gray-300 dark:border-gray-600 rounded mb-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
          >
            <option value="openai">OpenAI</option>
            <option value="google">Google Gemini</option>
            <option value="azure">Azure OpenAI</option>
          </select>
          
          <input
            type="text"
            placeholder={
              aiProvider === 'openai' ? 'Model (e.g., gpt-4o-mini)' :
              aiProvider === 'google' ? 'Model (e.g., gemini-2.0-flash-exp)' :
              'Model (e.g., gpt-4)'
            }
            value={modelName}
            onChange={(e) => setModelName(e.target.value)}
            className="w-full p-2 border border-gray-300 dark:border-gray-600 rounded mb-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400"
          />
          
          <input
            type="password"
            placeholder="API Key"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            className="w-full p-2 border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400"
          />
        </div>

        {/* MCP Server Settings */}
        <div className="mb-6">
          <h3 className="font-semibold mb-2 text-gray-900 dark:text-white">MCP Server</h3>
          <input
            type="text"
            placeholder="http://localhost:8000/mcp"
            value={mcpUrl}
            onChange={(e) => setMcpUrl(e.target.value)}
            className="w-full p-2 border border-gray-300 dark:border-gray-600 rounded mb-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400"
          />
          
          {/* OAuth Section */}
          <div className="mb-2 p-3 bg-blue-50 dark:bg-blue-900/20 rounded border border-blue-200 dark:border-blue-800">
            <div className="flex items-center justify-between mb-2">
              <label className="flex items-center text-sm text-gray-900 dark:text-white">
                <input
                  type="checkbox"
                  checked={useOAuth}
                  onChange={(e) => setUseOAuth(e.target.checked)}
                  className="mr-2"
                />
                Use OAuth Authentication
              </label>
            </div>
            
            {useOAuth && (
              <>
                <input
                  type="text"
                  placeholder="Client ID"
                  value={clientId}
                  onChange={(e) => setClientId(e.target.value)}
                  className="w-full p-2 border border-gray-300 dark:border-gray-600 rounded mb-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400 text-sm"
                />
                
                {!oauthMetadata && (
                  <button
                    onClick={discoverOAuth}
                    disabled={loading || !mcpUrl}
                    className="w-full bg-blue-500 dark:bg-blue-600 text-white p-2 rounded text-sm hover:bg-blue-600 dark:hover:bg-blue-700 disabled:bg-gray-300 dark:disabled:bg-gray-600 mb-2 transition-colors"
                  >
                    🔍 Discover OAuth Server
                  </button>
                )}
                
                {oauthMetadata && !mcpToken && (
                  <button
                    onClick={startOAuthFlow}
                    disabled={oauthInProgress || !clientId}
                    className="w-full bg-green-500 dark:bg-green-600 text-white p-2 rounded text-sm hover:bg-green-600 dark:hover:bg-green-700 disabled:bg-gray-300 dark:disabled:bg-gray-600 mb-2 transition-colors"
                  >
                    {oauthInProgress ? '⏳ Authenticating...' : '🔐 Start OAuth Flow'}
                  </button>
                )}
                
                {mcpToken && (
                  <div className="text-xs text-green-600 dark:text-green-400 mb-2">
                    ✅ OAuth token available
                  </div>
                )}
                
                {oauthMetadata && (
                  <div className="text-xs text-gray-600 dark:text-gray-400 mb-2">
                    <div>Auth Server: {new URL(oauthMetadata.authorization_endpoint).origin}</div>
                    {oauthMetadata.scopes_supported && oauthMetadata.scopes_supported.length > 0 && (
                      <div className="mt-1">
                        Required Scopes: <span className="font-mono">{oauthMetadata.scopes_supported.join(', ')}</span>
                      </div>
                    )}
                  </div>
                )}
                
                {/* Reset OAuth Button */}
                {(oauthMetadata || mcpToken || oauthInProgress) && (
                  <button
                    onClick={resetOAuthAuthentication}
                    className="w-full bg-red-500 dark:bg-red-600 text-white p-2 rounded text-sm hover:bg-red-600 dark:hover:bg-red-700 transition-colors"
                  >
                    🔄 Reset OAuth Authentication
                  </button>
                )}
              </>
            )}
          </div>
          
          {/* Manual Token Input (for non-OAuth or backup) */}
          {!useOAuth && (
            <input
              type="password"
              placeholder="OAuth Token (optional)"
              value={mcpToken}
              onChange={(e) => setMcpToken(e.target.value)}
              className="w-full p-2 border border-gray-300 dark:border-gray-600 rounded mb-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400"
            />
          )}
          
          <button
            onClick={connectMCP}
            disabled={loading || !mcpUrl || (useOAuth && !mcpToken)}
            className="w-full bg-blue-500 dark:bg-blue-600 text-white p-2 rounded hover:bg-blue-600 dark:hover:bg-blue-700 disabled:bg-gray-300 dark:disabled:bg-gray-600 transition-colors"
          >
            {connected ? '✅ Connected' : '🔌 Connect'}
          </button>
        </div>

        {/* Available Tools */}
        {tools.length > 0 && (
          <div>
            <h3 className="font-semibold mb-2 text-gray-900 dark:text-white">Available Tools ({tools.length})</h3>
            <div className="space-y-2">
              {tools.map(tool => (
                <div key={tool.name} className="p-2 bg-gray-50 dark:bg-gray-700 rounded text-sm">
                  <div className="font-medium text-gray-900 dark:text-white">{tool.name}</div>
                  <div className="text-gray-600 dark:text-gray-400 text-xs">{tool.description}</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Chat Area */}
      <div className="flex-1 flex flex-col">
        {/* Messages */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {messages.map((msg, idx) => (
            <div
              key={idx}
              className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              <div
                className={`max-w-2xl p-4 rounded-lg ${
                  msg.role === 'user'
                    ? 'bg-blue-500 dark:bg-blue-600 text-white'
                    : 'bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 text-gray-900 dark:text-white'
                }`}
              >
                <div className="whitespace-pre-wrap">{msg.content}</div>
              </div>
            </div>
          ))}
          {loading && (
            <div className="flex justify-start">
              <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 p-4 rounded-lg">
                <div className="flex items-center space-x-2">
                  <div className="w-2 h-2 bg-gray-400 dark:bg-gray-500 rounded-full animate-bounce"></div>
                  <div className="w-2 h-2 bg-gray-400 dark:bg-gray-500 rounded-full animate-bounce delay-100"></div>
                  <div className="w-2 h-2 bg-gray-400 dark:bg-gray-500 rounded-full animate-bounce delay-200"></div>
                </div>
              </div>
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>

        {/* Input */}
        <div className="p-6 bg-white dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700">
          <div className="flex space-x-4">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && sendMessage()}
              placeholder="Type your message..."
              className="flex-1 p-3 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-blue-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400"
              disabled={loading || !apiKey}
            />
            {messages.length > 0 && (
              <button
                onClick={() => setMessages([])}
                disabled={loading}
                className="px-4 py-3 bg-gray-500 dark:bg-gray-600 text-white rounded-lg hover:bg-gray-600 dark:hover:bg-gray-700 disabled:bg-gray-300 dark:disabled:bg-gray-600 transition-colors"
                title="Clear chat history"
              >
                🗑️ Clear
              </button>
            )}
            <button
              onClick={sendMessage}
              disabled={loading || !input.trim() || !apiKey}
              className="px-6 py-3 bg-blue-500 dark:bg-blue-600 text-white rounded-lg hover:bg-blue-600 dark:hover:bg-blue-700 disabled:bg-gray-300 dark:disabled:bg-gray-600 transition-colors"
            >
              Send
            </button>
          </div>
          
          {!apiKey && (
            <div className="mt-2 text-sm text-red-500 dark:text-red-400">
              ⚠️ Please enter an API key to start chatting
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
