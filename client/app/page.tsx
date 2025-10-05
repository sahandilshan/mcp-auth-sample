// app/page.tsx - Main AI Agent Chat Interface
'use client';

import { useState, useRef, useEffect } from 'react';
import { ThemeToggle } from './components/theme-toggle';

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

  // Connect to MCP Server
  const connectMCP = async () => {
    try {
      setLoading(true);
      
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
          
          <input
            type="password"
            placeholder="OAuth Token (optional)"
            value={mcpToken}
            onChange={(e) => setMcpToken(e.target.value)}
            className="w-full p-2 border border-gray-300 dark:border-gray-600 rounded mb-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400"
          />
          
          <button
            onClick={connectMCP}
            disabled={loading || !mcpUrl}
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
