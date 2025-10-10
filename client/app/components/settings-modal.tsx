'use client';

import { useState, useEffect } from 'react';
import {
  generatePKCE,
  generateState,
  buildAuthorizationUrl,
  storeOAuthState,
  retrieveOAuthState,
  clearOAuthState,
  storeTokens,
  type AuthorizationServerMetadata,
} from '../lib/oauth-utils';

export interface MCPServerConfig {
  id: string;
  name: string;
  url: string;
  useOAuth: boolean;
  clientId?: string;
  token?: string;
  oauthMetadata?: AuthorizationServerMetadata;
  enabled: boolean;
}

export interface AIProviderConfig {
  provider: 'openai' | 'google' | 'azure';
  apiKey: string;
  modelName: string;
}

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  aiConfig: AIProviderConfig;
  mcpServers: MCPServerConfig[];
  onSaveAIConfig: (config: AIProviderConfig) => void;
  onSaveMCPServers: (servers: MCPServerConfig[]) => void;
}

export default function SettingsModal({
  isOpen,
  onClose,
  aiConfig,
  mcpServers,
  onSaveAIConfig,
  onSaveMCPServers,
}: SettingsModalProps) {
  const [activeTab, setActiveTab] = useState<'ai' | 'mcp'>('ai');
  const [localAIConfig, setLocalAIConfig] = useState<AIProviderConfig>(aiConfig);
  const [localMCPServers, setLocalMCPServers] = useState<MCPServerConfig[]>(mcpServers);
  const [oauthInProgress, setOauthInProgress] = useState<string | null>(null);
  const [discoveryInProgress, setDiscoveryInProgress] = useState<string | null>(null);

  useEffect(() => {
    setLocalAIConfig(aiConfig);
  }, [aiConfig]);

  useEffect(() => {
    setLocalMCPServers(mcpServers);
  }, [mcpServers]);

  useEffect(() => {
    if (localAIConfig.provider === 'openai' && !localAIConfig.modelName) {
      setLocalAIConfig(prev => ({ ...prev, modelName: 'gpt-4o-mini' }));
    } else if (localAIConfig.provider === 'google' && !localAIConfig.modelName) {
      setLocalAIConfig(prev => ({ ...prev, modelName: 'gemini-2.0-flash-exp' }));
    } else if (localAIConfig.provider === 'azure' && !localAIConfig.modelName) {
      setLocalAIConfig(prev => ({ ...prev, modelName: 'gpt-4' }));
    }
  }, [localAIConfig.provider]);

  const handleSaveAI = () => {
    onSaveAIConfig(localAIConfig);
    alert('AI settings saved!');
  };

  const handleSaveMCP = () => {
    onSaveMCPServers(localMCPServers);
    alert('MCP server settings saved!');
  };

  const addServer = () => {
    setLocalMCPServers([...localMCPServers, {
      id: Date.now().toString(),
      name: 'New Server',
      url: '',
      useOAuth: false,
      enabled: true,
    }]);
  };

  const updateServer = (id: string, updates: Partial<MCPServerConfig>) => {
    setLocalMCPServers(localMCPServers.map(s => s.id === id ? { ...s, ...updates } : s));
  };

  const removeServer = (id: string) => {
    setLocalMCPServers(localMCPServers.filter(s => s.id !== id));
  };

  const discoverOAuth = async (serverId: string) => {
    const server = localMCPServers.find(s => s.id === serverId);
    if (!server?.url) {
      alert('Please enter a server URL first');
      return;
    }

    setDiscoveryInProgress(serverId);
    console.log('🔍 ========================================');
    console.log('🔍 Starting OAuth discovery for:', server.url);
    console.log('� ========================================');
    console.log('📡 Watch Network tab to see all discovery attempts!');
    console.log('');

    try {
      const url = new URL(server.url);
      const baseUrl = `${url.protocol}//${url.host}`;
      let metadata: AuthorizationServerMetadata | null = null;

      // Step 1: Try /.well-known/oauth-protected-resource (RFC 8414)
      console.log('📍 Step 1: Checking protected resource metadata (RFC 8414)...');
      console.log('   → GET', `${baseUrl}/.well-known/oauth-protected-resource`);
      try {
        const res1 = await fetch(`${baseUrl}/.well-known/oauth-protected-resource`, {
          headers: { 'Accept': 'application/json' },
        });
        console.log('   ← Status:', res1.status);
        
        if (res1.ok) {
          const protectedResourceMetadata = await res1.json();
          console.log('   ✅ Protected resource metadata found!');
          console.log('   📋', protectedResourceMetadata);
          
          if (protectedResourceMetadata.authorization_servers?.[0]) {
            const authServerUrl = protectedResourceMetadata.authorization_servers[0];
            console.log('   🎯 Found authorization server:', authServerUrl);
            console.log('   → GET', authServerUrl);
            
            const authRes = await fetch(authServerUrl, {
              headers: { 'Accept': 'application/json' },
            });
            console.log('   ← Status:', authRes.status);
            
            if (authRes.ok) {
              metadata = await authRes.json();
              if (metadata?.authorization_endpoint && metadata?.token_endpoint) {
                console.log('   ✅ Valid authorization server metadata found!');
              }
            }
          }
        } else {
          console.log('   ⚠️  Not found');
        }
      } catch (error) {
        console.log('   ❌', error instanceof Error ? error.message : 'Failed');
      }

      // Step 2: Try accessing protected resource (WWW-Authenticate)
      if (!metadata) {
        console.log('');
        console.log('📍 Step 2: Checking if resource is protected...');
        console.log('   → POST', server.url);
        try {
          const res2 = await fetch(server.url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              jsonrpc: '2.0',
              id: 0,
              method: 'initialize',
              params: {
                protocolVersion: '2024-11-05',
                capabilities: {},
                clientInfo: { name: 'mcp-oauth-client', version: '1.0.0' }
              }
            }),
          });
          console.log('   ← Status:', res2.status);
          
          if (res2.status === 401) {
            const wwwAuth = res2.headers.get('WWW-Authenticate');
            console.log('   ✅ Resource is protected!');
            console.log('   📋 WWW-Authenticate:', wwwAuth);
            
            if (wwwAuth) {
              const realmMatch = wwwAuth.match(/realm="([^"]+)"/);
              if (realmMatch?.[1]) {
                const authServerUrl = realmMatch[1];
                console.log('   🎯 Found authorization server in realm:', authServerUrl);
                console.log('   → GET', authServerUrl);
                
                const authRes = await fetch(authServerUrl, {
                  headers: { 'Accept': 'application/json' },
                });
                console.log('   ← Status:', authRes.status);
                
                if (authRes.ok) {
                  metadata = await authRes.json();
                  if (metadata?.authorization_endpoint && metadata?.token_endpoint) {
                    console.log('   ✅ Valid authorization server metadata found!');
                  }
                }
              } else {
                console.log('   ⚠️  No realm in WWW-Authenticate header');
              }
            }
          } else {
            console.log('   ⚠️  Not protected (expected 401)');
          }
        } catch (error) {
          console.log('   ❌', error instanceof Error ? error.message : 'Failed');
        }
      }

      // Step 3: Try /.well-known/oauth-authorization-server
      if (!metadata) {
        console.log('');
        console.log('📍 Step 3: Trying standard OAuth discovery...');
        console.log('   → GET', `${baseUrl}/.well-known/oauth-authorization-server`);
        try {
          const res3 = await fetch(`${baseUrl}/.well-known/oauth-authorization-server`, {
            headers: { 'Accept': 'application/json' },
          });
          console.log('   ← Status:', res3.status);
          
          if (res3.ok) {
            const data = await res3.json();
            if (data.authorization_endpoint && data.token_endpoint) {
              metadata = data;
              console.log('   ✅ Valid authorization server metadata found!');
            }
          } else {
            console.log('   ⚠️  Not found');
          }
        } catch (error) {
          console.log('   ❌', error instanceof Error ? error.message : 'Failed');
        }
      }

      // Step 4: Try /.well-known/openid-configuration
      if (!metadata) {
        console.log('');
        console.log('📍 Step 4: Trying OpenID Connect discovery...');
        console.log('   → GET', `${baseUrl}/.well-known/openid-configuration`);
        try {
          const res4 = await fetch(`${baseUrl}/.well-known/openid-configuration`, {
            headers: { 'Accept': 'application/json' },
          });
          console.log('   ← Status:', res4.status);
          
          if (res4.ok) {
            const data = await res4.json();
            if (data.authorization_endpoint && data.token_endpoint) {
              metadata = data;
              console.log('   ✅ Valid authorization server metadata found!');
            }
          } else {
            console.log('   ⚠️  Not found');
          }
        } catch (error) {
          console.log('   ❌', error instanceof Error ? error.message : 'Failed');
        }
      }

      if (metadata) {
        console.log('');
        console.log('✅ ========================================');
        console.log('✅ OAuth Discovery Successful!');
        console.log('✅ ========================================');
        console.log('📋 Authorization Server Metadata:');
        console.log('   - Issuer:', metadata.issuer);
        console.log('   - Authorization Endpoint:', metadata.authorization_endpoint);
        console.log('   - Token Endpoint:', metadata.token_endpoint);
        console.log('   - Supported Grant Types:', metadata.grant_types_supported);
        console.log('   - Supported Response Types:', metadata.response_types_supported);
        console.log('   - Code Challenge Methods:', metadata.code_challenge_methods_supported);
        console.log('');
        
        updateServer(serverId, { oauthMetadata: metadata });
        setDiscoveryInProgress(null);
        alert('✅ OAuth server discovered!\n\nCheck console for full details.');
      } else {
        throw new Error('No authorization server found');
      }
    } catch (error) {
      console.log('');
      console.log('❌ ========================================');
      console.log('❌ OAuth Discovery Failed');
      console.log('❌ ========================================');
      console.error(error);
      console.log('💡 Make sure your MCP server has one of:');
      console.log('   1. /.well-known/oauth-protected-resource (RFC 8414)');
      console.log('   2. Returns 401 with WWW-Authenticate header');
      console.log('   3. /.well-known/oauth-authorization-server endpoint');
      console.log('   4. /.well-known/openid-configuration endpoint');
      console.log('');
      
      setDiscoveryInProgress(null);
      alert(`Failed to discover OAuth server:\n${error instanceof Error ? error.message : 'Unknown error'}\n\nCheck console and Network tab for details.`);
    }
  };

  // NEW COMPREHENSIVE DISCOVERY - TRIES ALL VARIATIONS
  const discoverOAuthComprehensive = async (serverId: string) => {
    const server = localMCPServers.find(s => s.id === serverId);
    if (!server?.url) {
      alert('Please enter a server URL first');
      return;
    }

    setDiscoveryInProgress(serverId);
    console.log('🔍 Comprehensive OAuth Discovery');
    console.log('🔍 MCP:', server.url);
    console.log('📡 Trying ALL methods...');
    console.log('');

    try {
      const url = new URL(server.url);
      const baseUrl = `${url.protocol}//${url.host}`;
      const discoveredAuthServers: string[] = [];
      const allResults: Array<{step: string; url: string; status: 'success' | 'failed'; data?: any}> = [];
      
      const tryFetch = async (fetchUrl: string, label: string, method: 'GET' | 'POST' = 'GET', body?: any) => {
        try {
          console.log(`   ${method} ${fetchUrl}`);
          const res = await fetch(fetchUrl, {
            method,
            headers: method === 'POST' ? { 'Content-Type': 'application/json', 'Accept': 'application/json' } : { 'Accept': 'application/json' },
            body: body ? JSON.stringify(body) : undefined,
          });
          
          if (res.ok && method === 'GET') {
            const data = await res.json();
            console.log(`   ✅ ${res.status}`);
            allResults.push({ step: label, url: fetchUrl, status: 'success', data });
            return data;
          } else if (res.status === 401 && method === 'POST') {
            console.log(`   ✅ ${res.status} Protected`);
            return { status: 401, headers: Object.fromEntries(res.headers.entries()) };
          } else {
            console.log(`   ⚠️  ${res.status}`);
            allResults.push({ step: label, url: fetchUrl, status: 'failed' });
          }
        } catch (error) {
          console.log(`   ❌ ${error instanceof Error ? error.message : 'Failed'}`);
          allResults.push({ step: label, url: fetchUrl, status: 'failed' });
        }
        return null;
      };

      // Step 1
      console.log('📍 Step 1: Protected Resource Metadata');
      const pr = await tryFetch(`${baseUrl}/.well-known/oauth-protected-resource`, 'Protected Resource');
      if (pr?.authorization_servers) {
        discoveredAuthServers.push(...pr.authorization_servers);
        console.log('   🎯 Found:', pr.authorization_servers);
      }
      console.log('');

      // Step 2
      console.log('📍 Step 2: WWW-Authenticate');
      const ch = await tryFetch(server.url, 'Challenge', 'POST', { jsonrpc: '2.0', id: 0, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'mcp', version: '1.0.0' } } });
      if (ch?.status === 401 && ch.headers['www-authenticate']) {
        const m = ch.headers['www-authenticate'].match(/realm="([^"]+)"/);
        if (m?.[1]) {
          discoveredAuthServers.push(m[1]);
          console.log('   🎯 Realm:', m[1]);
        }
      }
      console.log('');

      // Step 3
      console.log('📍 Step 3: MCP Base URL');
      await tryFetch(`${baseUrl}/.well-known/oauth-authorization-server`, 'MCP OAuth');
      await tryFetch(`${baseUrl}/.well-known/openid-configuration`, 'MCP OIDC');
      console.log('');

      // Step 4
      if (discoveredAuthServers.length > 0) {
        console.log('📍 Step 4: Discovered Auth Servers');
        const unique = [...new Set(discoveredAuthServers)];
        for (const as of unique) {
          console.log(`   🔍 ${as}`);
          
          // 4a: Try the auth server URL directly
          await tryFetch(as, 'Direct');
          
          try {
            const au = new URL(as);
            const ab = `${au.protocol}//${au.host}`;
            
            // 4b: Try well-known paths on auth server's base URL (host only)
            if (ab !== baseUrl) {
              await tryFetch(`${ab}/.well-known/oauth-authorization-server`, 'AS Base OAuth');
              await tryFetch(`${ab}/.well-known/openid-configuration`, 'AS Base OIDC');
            }
            
            // 4c: NEW - Try well-known paths appended to FULL auth server URL (including path)
            // Example: https://api.asgardeo.io/t/sahan1001/oauth2/token/.well-known/oauth-authorization-server
            if (as !== ab) {
              // Remove trailing slash if present
              const asClean = as.endsWith('/') ? as.slice(0, -1) : as;
              await tryFetch(`${asClean}/.well-known/oauth-authorization-server`, 'AS Full OAuth');
              await tryFetch(`${asClean}/.well-known/openid-configuration`, 'AS Full OIDC');
            }
          } catch {}
        }
        console.log('');
      }

      // Results
      console.log('📊 Results');
      let best: AuthorizationServerMetadata | null = null;
      for (const r of allResults) {
        if (r.status === 'success' && r.data?.authorization_endpoint && r.data?.token_endpoint) {
          console.log(`✅ ${r.step}: ${r.url}`);
          if (!best) best = r.data;
        } else {
          console.log(`❌ ${r.step}: ${r.url}`);
        }
      }
      console.log('');

      if (best) {
        console.log(`✅ Using: ${best.authorization_endpoint}`);
        updateServer(serverId, { oauthMetadata: best });
        setDiscoveryInProgress(null);
        alert(`✅ Found ${allResults.filter(r => r.status === 'success').length} endpoint(s). Check console!`);
      } else {
        throw new Error('No valid metadata');
      }
    } catch (error) {
      console.log('❌ FAILED');
      setDiscoveryInProgress(null);
      alert(`❌ ${error}`);
    }
  };

  const startOAuthFlow = async (serverId: string) => {
    const server = localMCPServers.find(s => s.id === serverId);
    if (!server?.oauthMetadata || !server?.clientId) {
      alert('Please discover OAuth and enter Client ID first');
      return;
    }

    setOauthInProgress(serverId);
    try {
      const { codeVerifier, codeChallenge } = await generatePKCE();
      const state = generateState();
      
      const redirectUri = `${window.location.origin}/api/oauth/callback`;
      
      // Store OAuth state for verification
      const oauthState = {
        state,
        codeVerifier,
        redirectUri,
        mcpUrl: server.url,
        clientId: server.clientId,
      };
      storeOAuthState(oauthState);

      const authUrl = buildAuthorizationUrl(
        server.oauthMetadata.authorization_endpoint,
        server.clientId,
        redirectUri,
        state,
        codeChallenge,
        'S256',
        (server.oauthMetadata.scopes_supported || []).join(' ')
      );

      console.log('🔐 Starting OAuth flow...');
      console.log('   → Authorization URL:', authUrl);
      console.log('   📋 PKCE Challenge:', codeChallenge);

      const popup = window.open(authUrl, 'oauth-popup', 'width=600,height=700');
      if (!popup) throw new Error('Popup blocked');

      const handleMessage = async (event: MessageEvent) => {
        if (event.origin !== window.location.origin) return;
        
        // Handle OAuth error
        if (event.data.type === 'oauth-error') {
          window.removeEventListener('message', handleMessage);
          setOauthInProgress(null);
          const errorMsg = event.data.error_description || event.data.error;
          console.error('   ❌ OAuth error:', errorMsg);
          alert(`OAuth authorization failed: ${errorMsg}`);
          return;
        }
        
        // Handle OAuth success
        if (event.data.type !== 'oauth-callback') return;
        window.removeEventListener('message', handleMessage);

        const { code, state: returnedState } = event.data;
        console.log('   ← Received authorization code');
        console.log('   → Exchanging code for token...');
        
        const storedState = retrieveOAuthState();
        if (!storedState || storedState.state !== returnedState) {
          setOauthInProgress(null);
          throw new Error('Invalid state parameter');
        }

        // Exchange code for token - direct call to token endpoint
        console.log('   → POST', server.oauthMetadata!.token_endpoint);
        
        const tokenParams = new URLSearchParams({
          grant_type: 'authorization_code',
          code: code,
          redirect_uri: storedState.redirectUri,
          client_id: storedState.clientId,
          code_verifier: storedState.codeVerifier,
        });

        const tokenRes = await fetch(server.oauthMetadata!.token_endpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: tokenParams.toString(),
        });

        console.log('   ← Status:', tokenRes.status);

        if (!tokenRes.ok) {
          const errorText = await tokenRes.text();
          console.error('   ❌ Token exchange failed:', errorText);
          setOauthInProgress(null);
          throw new Error(`Token exchange failed: ${errorText}`);
        }

        const tokens = await tokenRes.json();
        console.log('   ✅ Tokens received!');
        console.log('   📋 Access token:', tokens.access_token?.substring(0, 20) + '...');
        
        if (tokens.access_token) {
          storeTokens(server.url, tokens);
          // Update server with token AND enable it
          updateServer(serverId, { 
            token: tokens.access_token,
            enabled: true 
          });
          clearOAuthState();
          setOauthInProgress(null);
          alert('✅ OAuth successful! Server enabled and ready to connect.');
        } else {
          setOauthInProgress(null);
          throw new Error('No access token in response');
        }
      };

      window.addEventListener('message', handleMessage);
      setTimeout(() => {
        window.removeEventListener('message', handleMessage);
        setOauthInProgress(null);
      }, 300000);
    } catch (error) {
      console.error('❌ OAuth flow failed:', error);
      alert(`OAuth failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      setOauthInProgress(null);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full max-w-3xl max-h-[90vh] overflow-hidden">
        <div className="flex items-center justify-between p-6 border-b border-gray-200 dark:border-gray-700">
          <h2 className="text-2xl font-semibold text-gray-900 dark:text-white">Settings</h2>
          <button
            onClick={onClose}
            className="text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 text-2xl"
          >
            ×
          </button>
        </div>

        <div className="flex border-b border-gray-200 dark:border-gray-700">
          <button
            onClick={() => setActiveTab('ai')}
            className={`flex-1 px-6 py-3 text-sm font-medium transition-colors ${
              activeTab === 'ai'
                ? 'text-blue-600 dark:text-blue-400 border-b-2 border-blue-600'
                : 'text-gray-500 dark:text-gray-400'
            }`}
          >
            AI Provider
          </button>
          <button
            onClick={() => setActiveTab('mcp')}
            className={`flex-1 px-6 py-3 text-sm font-medium transition-colors ${
              activeTab === 'mcp'
                ? 'text-blue-600 dark:text-blue-400 border-b-2 border-blue-600'
                : 'text-gray-500 dark:text-gray-400'
            }`}
          >
            MCP Servers
          </button>
        </div>

        <div className="p-6 overflow-y-auto max-h-[calc(90vh-180px)]">
          {activeTab === 'ai' && (
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  AI Provider
                </label>
                <select
                  value={localAIConfig.provider}
                  onChange={(e) =>
                    setLocalAIConfig({
                      ...localAIConfig,
                      provider: e.target.value as 'openai' | 'google' | 'azure',
                    })
                  }
                  className="w-full p-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                >
                  <option value="openai">OpenAI</option>
                  <option value="google">Google Gemini</option>
                  <option value="azure">Azure OpenAI</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  API Key
                </label>
                <input
                  type="password"
                  value={localAIConfig.apiKey}
                  onChange={(e) =>
                    setLocalAIConfig({ ...localAIConfig, apiKey: e.target.value })
                  }
                  placeholder="Enter your API key"
                  className="w-full p-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Model Name
                </label>
                <input
                  type="text"
                  value={localAIConfig.modelName}
                  onChange={(e) =>
                    setLocalAIConfig({ ...localAIConfig, modelName: e.target.value })
                  }
                  placeholder="e.g., gpt-4o-mini"
                  className="w-full p-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                />
              </div>

              <button
                onClick={handleSaveAI}
                className="w-full bg-blue-500 dark:bg-blue-600 text-white py-2 px-4 rounded-lg hover:bg-blue-600 dark:hover:bg-blue-700 transition-colors"
              >
                Save AI Settings
              </button>
            </div>
          )}

          {activeTab === 'mcp' && (
            <div className="space-y-4">
              {localMCPServers.map((server, index) => (
                <div
                  key={server.id}
                  className="border border-gray-300 dark:border-gray-600 rounded-lg p-4 space-y-3"
                >
                  <div className="flex items-center justify-between">
                    <h3 className="font-medium text-gray-900 dark:text-white">
                      Server {index + 1}
                    </h3>
                    <button
                      onClick={() => removeServer(server.id)}
                      className="text-red-500 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300"
                    >
                      Remove
                    </button>
                  </div>

                  <div className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      checked={server.enabled}
                      onChange={(e) =>
                        updateServer(server.id, { enabled: e.target.checked })
                      }
                      className="w-4 h-4"
                    />
                    <label className="text-sm text-gray-700 dark:text-gray-300">
                      Enable this server
                    </label>
                  </div>

                  <input
                    type="text"
                    value={server.name}
                    onChange={(e) => updateServer(server.id, { name: e.target.value })}
                    placeholder="Server Name"
                    className="w-full p-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  />

                  <input
                    type="text"
                    value={server.url}
                    onChange={(e) => updateServer(server.id, { url: e.target.value })}
                    placeholder="Server URL (e.g., http://localhost:8000/mcp)"
                    className="w-full p-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  />

                  <div className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      checked={server.useOAuth}
                      onChange={(e) =>
                        updateServer(server.id, { useOAuth: e.target.checked })
                      }
                      className="w-4 h-4"
                    />
                    <label className="text-sm text-gray-700 dark:text-gray-300">
                      Use OAuth Authentication
                    </label>
                  </div>

                  {server.useOAuth && (
                    <>
                      <input
                        type="text"
                        value={server.clientId || ''}
                        onChange={(e) =>
                          updateServer(server.id, { clientId: e.target.value })
                        }
                        placeholder="OAuth Client ID"
                        className="w-full p-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                      />

                      <div className="flex space-x-2">
                        <button
                          onClick={() => discoverOAuthComprehensive(server.id)}
                          disabled={discoveryInProgress === server.id}
                          className="flex-1 bg-green-500 dark:bg-green-600 text-white py-2 px-4 rounded-lg hover:bg-green-600 dark:hover:bg-green-700 transition-colors text-sm disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center"
                        >
                          {discoveryInProgress === server.id ? (
                            <>
                              <svg
                                className="animate-spin h-4 w-4 mr-2"
                                xmlns="http://www.w3.org/2000/svg"
                                fill="none"
                                viewBox="0 0 24 24"
                              >
                                <circle
                                  className="opacity-25"
                                  cx="12"
                                  cy="12"
                                  r="10"
                                  stroke="currentColor"
                                  strokeWidth="4"
                                ></circle>
                                <path
                                  className="opacity-75"
                                  fill="currentColor"
                                  d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                                ></path>
                              </svg>
                              Discovering...
                            </>
                          ) : (
                            'Discover OAuth Server'
                          )}
                        </button>

                        {server.oauthMetadata && (
                          <button
                            onClick={() => startOAuthFlow(server.id)}
                            disabled={oauthInProgress === server.id}
                            className="flex-1 bg-blue-500 dark:bg-blue-600 text-white py-2 px-4 rounded-lg hover:bg-blue-600 dark:hover:bg-blue-700 disabled:bg-gray-400 dark:disabled:bg-gray-600 transition-colors text-sm"
                          >
                            {oauthInProgress === server.id
                              ? 'Authenticating...'
                              : 'Authenticate'}
                          </button>
                        )}
                      </div>

                      {server.token && (
                        <div className="text-xs text-green-600 dark:text-green-400">
                          ✅ OAuth token available
                        </div>
                      )}
                    </>
                  )}

                  {!server.useOAuth && (
                    <input
                      type="password"
                      value={server.token || ''}
                      onChange={(e) =>
                        updateServer(server.id, { token: e.target.value })
                      }
                      placeholder="Bearer Token (optional)"
                      className="w-full p-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    />
                  )}
                </div>
              ))}

              <button
                onClick={addServer}
                className="w-full bg-gray-500 dark:bg-gray-600 text-white py-2 px-4 rounded-lg hover:bg-gray-600 dark:hover:bg-gray-700 transition-colors"
              >
                + Add Server
              </button>

              <button
                onClick={handleSaveMCP}
                className="w-full bg-blue-500 dark:bg-blue-600 text-white py-2 px-4 rounded-lg hover:bg-blue-600 dark:hover:bg-blue-700 transition-colors"
              >
                Save MCP Servers
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
