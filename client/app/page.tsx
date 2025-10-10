// app/page.tsx - Claude Desktop Style Chat Interface
'use client';

import { useState, useRef, useEffect } from 'react';
import { ThemeToggle } from './components/theme-toggle';
import SettingsModal, {
  type MCPServerConfig,
  type AIProviderConfig,
} from './components/settings-modal';

// Types
interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
  toolCalls?: Array<{
    name: string;
    input: any;
    result?: any;
  }>;
}

interface MCPTool {
  name: string;
  description: string;
  inputSchema: any;
}

interface MCPSession {
  sessionId: string;
  status: 'connecting' | 'connected' | 'error' | 'disconnected';
  serverName: string;
  mcpUrl: string;
  tools: MCPTool[];
  error?: string;
}

export default function MCPAgent() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  
  // MCP Sessions
  const [mcpSessions, setMcpSessions] = useState<MCPSession[]>([]);
  
  // AI Configuration
  const [aiConfig, setAiConfig] = useState<AIProviderConfig>({
    provider: 'openai',
    apiKey: '',
    modelName: 'gpt-4o-mini',
  });
  
  // MCP Servers Configuration
  const [mcpServers, setMcpServers] = useState<MCPServerConfig[]>([]);
  
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  // Load configurations from localStorage
  useEffect(() => {
    const savedAIConfig = localStorage.getItem('mcp-agent-ai-config');
    if (savedAIConfig) {
      try {
        setAiConfig(JSON.parse(savedAIConfig));
      } catch (e) {
        console.error('Error loading AI config:', e);
      }
    }

    const savedServers = localStorage.getItem('mcp-agent-mcp-servers');
    if (savedServers) {
      try {
        const servers: MCPServerConfig[] = JSON.parse(savedServers);
        setMcpServers(servers);
        
        // Auto-connect to enabled servers
        servers.filter(s => s.enabled).forEach(server => {
          connectToMCP(server);
        });
      } catch (e) {
        console.error('Error loading MCP servers:', e);
      }
    }
  }, []);

  // Auto-resize textarea
  const handleInputChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setInput(e.target.value);
    
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
      textareaRef.current.style.height = Math.min(textareaRef.current.scrollHeight, 200) + 'px';
    }
  };

  // Connect to MCP server
  const connectToMCP = async (server: MCPServerConfig) => {
    const newSessionId = `session-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
    
    // Add session as connecting
    const newSession: MCPSession = {
      sessionId: newSessionId,
      status: 'connecting',
      serverName: server.name,
      mcpUrl: server.url,
      tools: [],
    };
    
    setMcpSessions(prev => [...prev, newSession]);

    try {
      // Initialize MCP session - NO session ID on first request
      const initResponse = await fetch('/api/mcp', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'x-mcp-url': server.url,
          // Don't send session ID for initialize - server creates it
          ...(server.token && { 'x-mcp-token': server.token }),
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: {
            protocolVersion: '2024-11-05',
            capabilities: {
              sampling: {},
              tools: {},
            },
            clientInfo: {
              name: 'mcp-agent',
              version: '1.0.0',
            },
          },
        }),
      });

      if (!initResponse.ok) {
        throw new Error(`HTTP error! status: ${initResponse.status}`);
      }

      const initResult = await initResponse.json();
      console.log('MCP Initialize result:', initResult);

      // Get session ID from response header
      const serverSessionId = initResponse.headers.get('x-session-id');
      const actualSessionId = serverSessionId || newSessionId;
      
      console.log('Client session ID:', newSessionId);
      console.log('Server session ID:', serverSessionId);
      console.log('Using session ID:', actualSessionId);

      // Update session with actual session ID
      setMcpSessions(prev =>
        prev.map(s =>
          s.sessionId === newSessionId
            ? { ...s, sessionId: actualSessionId }
            : s
        )
      );

      // Send notifications/initialized to complete the handshake
      console.log('📤 Sending notifications/initialized...');
      const initializedResponse = await fetch('/api/mcp', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-mcp-url': server.url,
          'x-session-id': actualSessionId,
          ...(server.token && { 'x-mcp-token': server.token }),
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          method: 'notifications/initialized',
        }),
      });

      if (!initializedResponse.ok) {
        console.warn('Failed to send notifications/initialized:', initializedResponse.status);
      } else {
        console.log('✅ Initialization handshake complete');
      }

      // Get available tools
      console.log('🔧 Requesting tools list...');
      console.log('   Session ID:', actualSessionId);
      
      // MCP protocol requires params field even if empty
      let toolsRequestBody = {
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/list',
        params: {},
      };
      
      const toolsResponse = await fetch('/api/mcp', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'x-mcp-url': server.url,
          'x-session-id': actualSessionId,
          ...(server.token && { 'x-mcp-token': server.token }),
        },
        body: JSON.stringify(toolsRequestBody),
      });

      if (!toolsResponse.ok) {
        const errorText = await toolsResponse.text();
        console.error('❌ Tools list HTTP error:', toolsResponse.status, errorText);
        throw new Error(`HTTP error! status: ${toolsResponse.status}`);
      }

      const toolsResult = await toolsResponse.json();
      console.log('🔧 Tools list response:', toolsResult);
      
      if (toolsResult.error) {
        console.error('❌ Tools list error:', toolsResult.error);
        throw new Error(`MCP error: ${toolsResult.error.message}`);
      }

      const toolsList = toolsResult.result?.tools || [];

      // Update session with tools using actual session ID
      setMcpSessions(prev =>
        prev.map(s =>
          s.sessionId === actualSessionId
            ? { ...s, status: 'connected', tools: toolsList }
            : s
        )
      );
    } catch (error) {
      console.error('Error connecting to MCP:', error);
      setMcpSessions(prev =>
        prev.map(s =>
          s.sessionId === newSessionId || s.serverName === server.name
            ? { ...s, status: 'error', error: error instanceof Error ? error.message : 'Unknown error' }
            : s
        )
      );
    }
  };

  // Call MCP tool
  const callMCPTool = async (
    toolName: string,
    toolInput: any,
    session: MCPSession
  ): Promise<any> => {
    try {
      const server = mcpServers.find(s => s.url === session.mcpUrl);

      const response = await fetch('/api/mcp', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'x-mcp-url': session.mcpUrl,
          'x-session-id': session.sessionId,
          ...(server?.token && { 'x-mcp-token': server.token }),
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: Date.now(),
          method: 'tools/call',
          params: {
            name: toolName,
            arguments: toolInput,
          },
        }),
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const result = await response.json();
      return result.result;
    } catch (error) {
      console.error('Error calling MCP tool:', error);
      throw error;
    }
  };

  // Get all available tools from all connected sessions
  const getAllTools = () => {
    const allTools: Array<MCPTool & { sessionId: string; serverName: string }> = [];
    
    mcpSessions.forEach(session => {
      if (session.status === 'connected') {
        session.tools.forEach(tool => {
          allTools.push({
            ...tool,
            sessionId: session.sessionId,
            serverName: session.serverName,
          });
        });
      }
    });
    
    return allTools;
  };

  // OpenAI chat completion
  const sendMessageOpenAI = async (conversationMessages: Message[]) => {
    if (!aiConfig?.apiKey) {
      throw new Error('OpenAI API key not configured');
    }

    const allTools = getAllTools();
    
    // Convert MCP tools to OpenAI function format
    const functions = allTools.map(tool => ({
      type: 'function' as const,
      function: {
        name: tool.name,
        description: tool.description,
        parameters: tool.inputSchema,
      },
    }));

    const openaiMessages = conversationMessages.map(msg => ({
      role: msg.role,
      content: msg.content,
    }));

    let response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${aiConfig.apiKey}`,
      },
      body: JSON.stringify({
        model: aiConfig.modelName || 'gpt-4o-mini',
        messages: openaiMessages,
        tools: functions.length > 0 ? functions : undefined,
        tool_choice: functions.length > 0 ? 'auto' : undefined,
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`OpenAI API error: ${error}`);
    }

    let result = await response.json();
    let assistantMessage = result.choices[0].message;

    // Handle tool calls
    const toolCalls: Array<{ name: string; input: any; result: any }> = [];
    
    while (assistantMessage.tool_calls && assistantMessage.tool_calls.length > 0) {
      console.log('Tool calls:', assistantMessage.tool_calls);

      // Execute all tool calls
      const toolResults = await Promise.all(
        assistantMessage.tool_calls.map(async (toolCall: any) => {
          const toolName = toolCall.function.name;
          const toolInput = JSON.parse(toolCall.function.arguments);
          
          // Find which session has this tool
          const toolInfo = allTools.find(t => t.name === toolName);
          if (!toolInfo) {
            return {
              tool_call_id: toolCall.id,
              role: 'tool',
              name: toolName,
              content: JSON.stringify({ error: 'Tool not found' }),
            };
          }

          const session = mcpSessions.find(s => s.sessionId === toolInfo.sessionId);
          if (!session) {
            return {
              tool_call_id: toolCall.id,
              role: 'tool',
              name: toolName,
              content: JSON.stringify({ error: 'Session not found' }),
            };
          }

          try {
            const result = await callMCPTool(toolName, toolInput, session);
            toolCalls.push({ name: toolName, input: toolInput, result });
            
            return {
              tool_call_id: toolCall.id,
              role: 'tool',
              name: toolName,
              content: JSON.stringify(result),
            };
          } catch (error) {
            return {
              tool_call_id: toolCall.id,
              role: 'tool',
              name: toolName,
              content: JSON.stringify({ error: error instanceof Error ? error.message : 'Unknown error' }),
            };
          }
        })
      );

      // Continue conversation with tool results
      openaiMessages.push(assistantMessage);
      openaiMessages.push(...toolResults);

      response = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${aiConfig.apiKey}`,
        },
        body: JSON.stringify({
          model: aiConfig.modelName || 'gpt-4o-mini',
          messages: openaiMessages,
          tools: functions.length > 0 ? functions : undefined,
          tool_choice: functions.length > 0 ? 'auto' : undefined,
        }),
      });

      if (!response.ok) {
        const error = await response.text();
        throw new Error(`OpenAI API error: ${error}`);
      }

      result = await response.json();
      assistantMessage = result.choices[0].message;
    }

    return {
      content: assistantMessage.content,
      toolCalls,
    };
  };

  // Helper function to resolve JSON Schema $ref references
  const resolveSchemaRefs = (schema: any): any => {
    if (!schema || typeof schema !== 'object') {
      return schema;
    }

    // If this object has a $ref, resolve it
    if (schema.$ref && typeof schema.$ref === 'string') {
      const refPath = schema.$ref.split('/');
      if (refPath[0] === '#' && refPath[1] === '$defs') {
        const defName = refPath[2];
        if (schema.$defs && schema.$defs[defName]) {
          // Resolve the reference
          const resolved = resolveSchemaRefs(schema.$defs[defName]);
          // Remove $ref and $defs, keep other properties
          const { $ref, $defs, ...rest } = schema;
          return { ...resolved, ...rest };
        }
      }
    }

    // Recursively resolve refs in the schema
    const result: any = Array.isArray(schema) ? [] : {};
    for (const key in schema) {
      if (key === '$defs') {
        // Skip $defs in the output, but keep for resolution
        continue;
      }
      result[key] = resolveSchemaRefs(schema[key]);
    }

    // If we have $defs at root level, resolve references in properties
    if (schema.$defs && schema.properties) {
      for (const propKey in result.properties) {
        const prop = result.properties[propKey];
        if (prop.$ref && typeof prop.$ref === 'string') {
          const refPath = prop.$ref.split('/');
          if (refPath[0] === '#' && refPath[1] === '$defs') {
            const defName = refPath[2];
            if (schema.$defs[defName]) {
              result.properties[propKey] = resolveSchemaRefs(schema.$defs[defName]);
            }
          }
        }
      }
    }

    return result;
  };

  // Google Gemini chat completion
  const sendMessageGemini = async (conversationMessages: Message[]) => {
    if (!aiConfig?.apiKey) {
      throw new Error('Google API key not configured');
    }

    const allTools = getAllTools();

    // Convert MCP tools to Gemini function format
    // Gemini doesn't support $defs and $ref, so we need to resolve them
    const functionDeclarations = allTools.map(tool => ({
      name: tool.name,
      description: tool.description,
      parameters: resolveSchemaRefs(tool.inputSchema),
    }));

    // Convert messages to Gemini format
    const contents = conversationMessages.map(msg => ({
      role: msg.role === 'assistant' ? 'model' : 'user',
      parts: [{ text: msg.content }],
    }));

    const requestBody: any = {
      contents,
    };

    if (functionDeclarations.length > 0) {
      requestBody.tools = [{ functionDeclarations }];
    }

    let response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${aiConfig.modelName || 'gemini-2.0-flash-exp'}:generateContent?key=${aiConfig.apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody),
      }
    );

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Gemini API error: ${error}`);
    }

    let result = await response.json();
    let candidate = result.candidates[0];

    const toolCalls: Array<{ name: string; input: any; result: any }> = [];

    // Handle function calls
    while (
      candidate.content.parts &&
      candidate.content.parts.some((part: any) => part.functionCall)
    ) {
      console.log('Function calls:', candidate.content.parts);

      // Execute all function calls
      const functionResponses = await Promise.all(
        candidate.content.parts
          .filter((part: any) => part.functionCall)
          .map(async (part: any) => {
            const functionCall = part.functionCall;
            const toolName = functionCall.name;
            const toolInput = functionCall.args;

            // Find which session has this tool
            const toolInfo = allTools.find(t => t.name === toolName);
            if (!toolInfo) {
              return {
                functionResponse: {
                  name: toolName,
                  response: { error: 'Tool not found' },
                },
              };
            }

            const session = mcpSessions.find(s => s.sessionId === toolInfo.sessionId);
            if (!session) {
              return {
                functionResponse: {
                  name: toolName,
                  response: { error: 'Session not found' },
                },
              };
            }

            try {
              const result = await callMCPTool(toolName, toolInput, session);
              toolCalls.push({ name: toolName, input: toolInput, result });
              
              return {
                functionResponse: {
                  name: toolName,
                  response: result,
                },
              };
            } catch (error) {
              return {
                functionResponse: {
                  name: toolName,
                  response: { error: error instanceof Error ? error.message : 'Unknown error' },
                },
              };
            }
          })
      );

      // Continue conversation with function responses
      contents.push(candidate.content);
      contents.push({
        role: 'user',
        parts: functionResponses,
      });

      const continueRequestBody: any = {
        contents,
      };

      if (functionDeclarations.length > 0) {
        continueRequestBody.tools = [{ functionDeclarations }];
      }

      response = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/${aiConfig.modelName || 'gemini-2.0-flash-exp'}:generateContent?key=${aiConfig.apiKey}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(continueRequestBody),
        }
      );

      if (!response.ok) {
        const error = await response.text();
        throw new Error(`Gemini API error: ${error}`);
      }

      result = await response.json();
      candidate = result.candidates[0];
    }

    const textPart = candidate.content.parts.find((part: any) => part.text);
    return {
      content: textPart?.text || '',
      toolCalls,
    };
  };

  // Handle sending message
  const handleSendMessage = async () => {
    if (!input.trim() || loading) return;

    if (!aiConfig || !aiConfig.apiKey) {
      alert('Please configure AI settings first');
      setShowSettings(true);
      return;
    }

    const userMessage: Message = {
      id: `msg-${Date.now()}`,
      role: 'user',
      content: input.trim(),
      timestamp: new Date(),
    };

    setMessages(prev => [...prev, userMessage]);
    setInput('');
    setLoading(true);

    // Reset textarea height
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
    }

    try {
      const conversationMessages = [...messages, userMessage];

      let result;
      if (aiConfig.provider === 'openai' || aiConfig.provider === 'azure') {
        result = await sendMessageOpenAI(conversationMessages);
      } else if (aiConfig.provider === 'google') {
        result = await sendMessageGemini(conversationMessages);
      } else {
        throw new Error('Unsupported AI provider');
      }

      const assistantMessage: Message = {
        id: `msg-${Date.now()}`,
        role: 'assistant',
        content: result.content,
        timestamp: new Date(),
        toolCalls: result.toolCalls.length > 0 ? result.toolCalls : undefined,
      };

      setMessages(prev => [...prev, assistantMessage]);
    } catch (error) {
      console.error('Error sending message:', error);
      const errorMessage: Message = {
        id: `msg-${Date.now()}`,
        role: 'assistant',
        content: `Error: ${error instanceof Error ? error.message : 'Unknown error'}`,
        timestamp: new Date(),
      };
      setMessages(prev => [...prev, errorMessage]);
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  // Save AI config callback
  const handleSaveAIConfig = (newConfig: AIProviderConfig) => {
    setAiConfig(newConfig);
    localStorage.setItem('mcp-agent-ai-config', JSON.stringify(newConfig));
  };

  // Save MCP servers callback
  const handleSaveMCPServers = (newServers: MCPServerConfig[]) => {
    setMcpServers(newServers);
    localStorage.setItem('mcp-agent-mcp-servers', JSON.stringify(newServers));

    // Disconnect all current sessions
    setMcpSessions([]);

    // Connect to enabled servers
    newServers.filter(s => s.enabled).forEach(server => {
      connectToMCP(server);
    });
  };

  return (
    <div className="flex flex-col h-screen bg-white dark:bg-gray-950">
      {/* Header */}
      <header className="flex items-center justify-between px-4 py-3 border-b border-gray-200 dark:border-gray-800">
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-semibold text-gray-900 dark:text-white">
            MCP Agent
          </h1>
          
          {/* MCP Server Status */}
          {mcpSessions.length > 0 && (
            <div className="flex gap-2">
              {mcpSessions.map(session => (
                <div
                  key={session.sessionId}
                  className="flex items-center gap-2 px-2 py-1 rounded-md bg-gray-100 dark:bg-gray-800 text-xs"
                  title={session.error || session.status}
                >
                  <div
                    className={`w-2 h-2 rounded-full ${
                      session.status === 'connected'
                        ? 'bg-green-500'
                        : session.status === 'error'
                        ? 'bg-red-500'
                        : 'bg-yellow-500'
                    }`}
                  />
                  <span className="text-gray-700 dark:text-gray-300">
                    {session.serverName}
                  </span>
                  {session.status === 'connected' && (
                    <span className="text-gray-500 dark:text-gray-400">
                      ({session.tools.length} tools)
                    </span>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowSettings(true)}
            className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
            title="Settings"
          >
            <svg
              className="w-5 h-5 text-gray-700 dark:text-gray-300"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"
              />
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"
              />
            </svg>
          </button>
          <ThemeToggle />
        </div>
      </header>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto">
        <div className="max-w-3xl mx-auto px-4 py-8">
          {messages.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-center">
              <div className="mb-8">
                <svg
                  className="w-16 h-16 text-gray-300 dark:text-gray-700 mx-auto mb-4"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z"
                  />
                </svg>
                <h2 className="text-2xl font-semibold text-gray-900 dark:text-white mb-2">
                  Welcome to MCP Agent
                </h2>
                <p className="text-gray-600 dark:text-gray-400">
                  Configure your AI provider and MCP servers to get started
                </p>
              </div>
              
              {(!aiConfig || !aiConfig.apiKey) && (
                <button
                  onClick={() => setShowSettings(true)}
                  className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                >
                  Open Settings
                </button>
              )}
            </div>
          ) : (
            <div className="space-y-6">
              {messages.map(message => (
                <div
                  key={message.id}
                  className={`flex ${
                    message.role === 'user' ? 'justify-end' : 'justify-start'
                  }`}
                >
                  <div
                    className={`max-w-[80%] rounded-2xl px-4 py-3 ${
                      message.role === 'user'
                        ? 'bg-blue-600 text-white'
                        : 'bg-gray-100 dark:bg-gray-800 text-gray-900 dark:text-white'
                    }`}
                  >
                    <div className="whitespace-pre-wrap break-words">
                      {message.content}
                    </div>
                    
                    {message.toolCalls && message.toolCalls.length > 0 && (
                      <div className="mt-3 pt-3 border-t border-gray-200 dark:border-gray-700">
                        <div className="text-sm opacity-75 mb-2">
                          Tool Calls:
                        </div>
                        {message.toolCalls.map((call, idx) => (
                          <div
                            key={idx}
                            className="text-xs mb-2 p-2 rounded bg-gray-200 dark:bg-gray-700"
                          >
                            <div className="font-semibold">{call.name}</div>
                            <div className="opacity-75 mt-1">
                              Input: {JSON.stringify(call.input)}
                            </div>
                            {call.result && (
                              <div className="opacity-75 mt-1">
                                Result: {JSON.stringify(call.result)}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              ))}
              <div ref={messagesEndRef} />
            </div>
          )}
        </div>
      </div>

      {/* Input */}
      <div className="border-t border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-950">
        <div className="max-w-3xl mx-auto px-4 py-4">
          <div className="relative flex items-end gap-2">
            <textarea
              ref={textareaRef}
              value={input}
              onChange={handleInputChange}
              onKeyDown={handleKeyDown}
              placeholder="Type a message..."
              rows={1}
              disabled={loading}
              className="flex-1 resize-none rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 px-4 py-3 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-600 disabled:opacity-50 min-h-[48px] max-h-[200px]"
            />
            <button
              onClick={handleSendMessage}
              disabled={loading || !input.trim()}
              className="px-4 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {loading ? (
                <svg
                  className="animate-spin h-5 w-5"
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
              ) : (
                <svg
                  className="w-5 h-5"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8"
                  />
                </svg>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Settings Modal */}
      {showSettings && (
        <SettingsModal
          isOpen={showSettings}
          onClose={() => setShowSettings(false)}
          aiConfig={aiConfig}
          mcpServers={mcpServers}
          onSaveAIConfig={handleSaveAIConfig}
          onSaveMCPServers={handleSaveMCPServers}
        />
      )}
    </div>
  );
}