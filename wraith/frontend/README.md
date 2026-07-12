# Wraith Frontend

Interactive visualization for the Wraith autonomous bug-bounty pipeline.

## Features
- **Attack Surface Graph**: Interactive force-directed graph of discovered assets and findings.
- **Agent Activity Feed**: Real-time streaming of AI agent reasoning steps via SSE.

## Getting Started

### Prerequisites
- Node.js 18+
- Active `graph_db` and `exploit_agent` services
- **Build-time network access**: Required for `next/font/google` to fetch Geist and JetBrains Mono from fonts.googleapis.com.

### Environment Variables
Create a `.env.local` file in this directory:
```bash
NEXT_PUBLIC_GRAPH_DB_URL=http://localhost:8001/api/v1
NEXT_PUBLIC_AGENT_URL=http://localhost:8003/api/v1
```

### Installation
```bash
npm install
```

### Development
```bash
npm run dev
```
The UI will be available at `http://localhost:3000`.

## Testing
```bash
npm test
```
