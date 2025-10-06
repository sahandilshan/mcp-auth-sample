# MCP AI Agent Client

A Next.js web client for connecting to MCP (Model Context Protocol) servers with OAuth 2.0 authentication support. Chat with AI models that can automatically discover and use tools from your MCP server.

## Features

-  **Multiple AI Providers** - OpenAI, Google Gemini, and Azure OpenAI
-  **Automatic Tool Discovery** - AI discovers and uses MCP server tools
-  **OAuth 2.0 Authentication** - Automatic discovery with PKCE flow
-  **Dark/Light Mode** - Beautiful themed UI
-  **CORS Proxy** - Built-in proxy to avoid CORS issues
-  **Docker Ready** - Easy containerized deployment

## Quick Start

### Option 1: Docker Compose (Recommended)

```bash
docker-compose up -d
```

Access at http://localhost:3000

### Option 2: Docker

```bash
docker build -t mcp-ai-agent .
docker run -d -p 3000:3000 --name mcp-ai-agent mcp-ai-agent
```

### Option 3: Local Development

```bash
npm install
npm run dev
```

## How to Use

1. **Configure AI Provider**
   - Select your AI provider (OpenAI, Google Gemini, or Azure OpenAI)
   - Enter your API key
   - Enter model name:
     - OpenAI: ```gpt-4o-mini``` or ```gpt-4```
     - Google: ```gemini-2.0-flash-exp``` (without models/ prefix)
     - Azure: Your deployment name

2. **Connect to MCP Server**
   - Enter your MCP server URL
     - Local: ```http://localhost:8000/mcp```
     - Docker: ```http://host.docker.internal:8000/mcp```
     - Remote: ```https://your-server.com/mcp```

3. **Optional: OAuth Authentication**
   - Enable Use OAuth Authentication
   - Click Discover OAuth Server
   - Enter your OAuth Client ID
   - Complete the OAuth flow in the popup

4. **Start Chatting**
   - Click Connect
   - Available tools appear in the sidebar
   - AI automatically uses MCP tools when needed

## Docker Commands

### Docker Compose

```bash
# Start
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down

# Rebuild
docker-compose up -d --build
```

### Docker CLI

```bash
# Build
docker build -t mcp-ai-agent .

# Run
docker run -d -p 3000:3000 --name mcp-ai-agent mcp-ai-agent

# Logs
docker logs -f mcp-ai-agent

# Stop
docker stop mcp-ai-agent

# Remove
docker rm mcp-ai-agent
```

### Change Port

Edit docker-compose.yml:

```yaml
ports:
  - "8080:3000"
```

Or with Docker CLI:

```bash
docker run -d -p 8080:3000 --name mcp-ai-agent mcp-ai-agent
```

## Troubleshooting

### Port Already in Use

```powershell
# Find what's using the port
netstat -ano | findstr :3000

# Kill the process
taskkill /PID <PID> /F
```

Or change the port (see Docker Commands above).

### Can't Connect to Localhost MCP Server

When running in Docker, use http://host.docker.internal:8000/mcp instead of http://localhost:8000/mcp.

### Google Gemini CORS Error

Enter model name WITHOUT the models/ prefix:

- Correct: gemini-2.0-flash-exp
- Wrong: models/gemini-2.0-flash-exp

### Docker Build Fails

Clear cache and rebuild:

```bash
docker build --no-cache -t mcp-ai-agent .
# or
docker-compose build --no-cache
```

## Technologies

- Next.js 15
- React 19
- TypeScript
- Tailwind CSS
- Model Context Protocol
- Docker

## Additional Documentation

- **OAUTH_README.md** - OAuth authentication setup
- **OAUTH_EXAMPLES.md** - OAuth configuration examples
- **README_DOCKER.md** - Detailed Docker guide

## License

MIT
