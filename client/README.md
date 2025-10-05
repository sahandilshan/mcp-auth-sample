# MCP AI Agent ClientThis is a [Next.js](https://nextjs.org) project bootstrapped with [`create-next-app`](https://nextjs.org/docs/app/api-reference/cli/create-next-app).



A Next.js web client for connecting to MCP (Model Context Protocol) servers with OAuth authentication support. This client allows AI models (OpenAI, Google Gemini, Azure OpenAI) to interact with MCP tools through a chat interface.## Getting Started



## FeaturesFirst, run the development server:



- 🔐 **MCP OAuth Authentication** - Supports standard MCP authentication with Bearer tokens```bash

- 🔄 **Session Management** - Proper MCP protocol session initialization and managementnpm run dev

- 🤖 **Multiple AI Providers** - OpenAI, Google Gemini, and Azure OpenAI support# or

- 🛠️ **Tool Discovery** - Automatically discovers and uses MCP server toolsyarn dev

- 🎨 **Dark/Light Mode** - Beautiful UI with theme support# or

- 🔌 **CORS Proxy** - Built-in proxy to avoid CORS issuespnpm dev

# or

## Prerequisitesbun dev

```

- Node.js 18.x or higher

- npm or yarn package managerOpen [http://localhost:3000](http://localhost:3000) with your browser to see the result.

- An MCP server running (e.g., `http://localhost:8000/mcp`)

- API key for your chosen AI provider (OpenAI, Google, or Azure)You can start editing the page by modifying `app/page.tsx`. The page auto-updates as you edit the file.



## InstallationThis project uses [`next/font`](https://nextjs.org/docs/app/building-your-application/optimizing/fonts) to automatically optimize and load [Geist](https://vercel.com/font), a new font family for Vercel.



1. **Clone the repository**## Learn More

   ```bash

   git clone <your-repo-url>To learn more about Next.js, take a look at the following resources:

   cd client

   ```- [Next.js Documentation](https://nextjs.org/docs) - learn about Next.js features and API.

- [Learn Next.js](https://nextjs.org/learn) - an interactive Next.js tutorial.

2. **Install dependencies**

   ```bashYou can check out [the Next.js GitHub repository](https://github.com/vercel/next.js) - your feedback and contributions are welcome!

   npm install

   ```## Deploy on Vercel



3. **Run the development server**The easiest way to deploy your Next.js app is to use the [Vercel Platform](https://vercel.com/new?utm_medium=default-template&filter=next.js&utm_source=create-next-app&utm_campaign=create-next-app-readme) from the creators of Next.js.

   ```bash

   npm run devCheck out our [Next.js deployment documentation](https://nextjs.org/docs/app/building-your-application/deploying) for more details.

   ```

4. **Open your browser**
   Navigate to `http://localhost:3000` (or the port shown in terminal)

## Usage

### 1. Configure AI Provider
- Select your AI provider (OpenAI, Google Gemini, or Azure OpenAI)
- Enter your API key

### 2. Connect to MCP Server
- Enter your MCP server URL (e.g., `http://localhost:8000/mcp`)
- Optionally enter your OAuth Bearer token if authentication is required
- Click "Connect"

### 3. Chat with AI
- Once connected, available tools will be shown in the sidebar
- Type your message and the AI will automatically use MCP tools when needed
- Tool results are displayed in the conversation

## Project Structure

```
client/
├── app/
│   ├── api/
│   │   └── mcp/
│   │       └── route.ts          # MCP proxy API endpoint
│   ├── components/
│   │   ├── theme-provider.tsx    # Theme context provider
│   │   └── theme-toggle.tsx      # Dark/light mode toggle
│   ├── favicon.ico
│   ├── globals.css               # Global styles
│   ├── layout.tsx                # Root layout
│   └── page.tsx                  # Main chat interface
├── public/                        # Static assets
├── .gitignore
├── eslint.config.mjs             # ESLint configuration
├── next.config.ts                # Next.js configuration
├── package.json                  # Dependencies and scripts
├── postcss.config.cjs            # PostCSS configuration
├── README.md                     # This file
├── tailwind.config.js            # Tailwind CSS configuration
└── tsconfig.json                 # TypeScript configuration
```

## Configuration Files

### Essential Files to Commit

**Core Application:**
- `app/` - All application code
  - `page.tsx` - Main chat interface
  - `layout.tsx` - Root layout
  - `globals.css` - Styles
  - `api/mcp/route.ts` - Proxy endpoint
  - `components/` - Reusable components

**Configuration:**
- `package.json` - Dependencies list
- `package-lock.json` - Locked dependency versions (optional but recommended)
- `next.config.ts` - Next.js settings
- `tsconfig.json` - TypeScript settings
- `tailwind.config.js` - Tailwind CSS settings
- `postcss.config.cjs` - PostCSS settings
- `eslint.config.mjs` - Linting rules

**Documentation:**
- `README.md` - This file
- `.gitignore` - Files to ignore

### Files NOT to Commit (already in .gitignore)

- `node_modules/` - Dependencies (installed via npm)
- `.next/` - Build output
- `.env*` - Environment variables (secrets)
- `next-env.d.ts` - Auto-generated

## MCP Protocol Implementation

This client implements the MCP specification:

1. **Initialize** - Sends `initialize` request with protocol version and capabilities
2. **Session Management** - Tracks session ID from server responses
3. **Initialized Notification** - Confirms initialization
4. **Tool Discovery** - Lists available tools via `tools/list`
5. **Tool Execution** - Calls tools via `tools/call` with session context

### SSE Support

The proxy handles both JSON and Server-Sent Events (SSE) responses from MCP servers, as required by the MCP HTTP transport specification.

## Available Scripts

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm start` - Start production server

## Environment Variables (Optional)

You can create a `.env.local` file for default values (not recommended for secrets):

```env
# Example - better to enter in UI
NEXT_PUBLIC_MCP_URL=http://localhost:8000/mcp
```

## Troubleshooting

### CORS Errors
The built-in proxy at `/api/mcp` handles CORS. Make sure you're using the proxy (requests should go to `/api/mcp`, not directly to your MCP server).

### Session ID Errors
Ensure your MCP server implements proper session management. The client sends:
- `initialize` method first
- Extracts session ID from headers
- Includes session ID in all subsequent requests

### Connection Refused
- Verify your MCP server is running
- Check the MCP server URL is correct
- Ensure the server accepts HTTP POST requests with JSON-RPC 2.0 format

## Technologies Used

- **Next.js 15** - React framework
- **React 19** - UI library
- **TypeScript** - Type safety
- **Tailwind CSS** - Styling
- **Model Context Protocol** - Server communication

## License

MIT License

## Related Links

- [MCP Specification](https://modelcontextprotocol.io/)
- [Next.js Documentation](https://nextjs.org/docs)
- [Tailwind CSS](https://tailwindcss.com/)
