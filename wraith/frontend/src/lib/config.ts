export const config = {
  graphDbUrl: process.env.NEXT_PUBLIC_GRAPH_DB_URL || 'http://localhost:8001/api/v1',
  agentUrl: process.env.NEXT_PUBLIC_AGENT_URL || 'http://localhost:8003/api/v1',
};
