export const config = {
  graphDbUrl: process.env.NEXT_PUBLIC_GRAPH_DB_URL || 'http://localhost:8001/api/v1',
  agentUrl: process.env.NEXT_PUBLIC_AGENT_URL || 'http://localhost:8003/api/v1',
  reconUrl: process.env.NEXT_PUBLIC_RECON_URL || 'http://localhost:8002/api/v1',
  exploitRunnerUrl: process.env.NEXT_PUBLIC_EXPLOIT_RUNNER_URL || 'http://localhost:8004/api/v1',
  reportingUrl: process.env.NEXT_PUBLIC_REPORTING_URL || 'http://localhost:8006/api/v1',
};
