# Wraith — Phase 2: Recon Orchestrator

The Recon Orchestrator service coordinates reconnaissance tasks by spawning multiple tool containers in parallel and streaming results to the `graph_db` service.

## Features
- Parallel tool execution using `asyncio`.
- Ephemeral Docker containers for each tool run.
- Resource limits on tool containers (512MB RAM, 0.5 CPU).
- Incremental data streaming to `graph_db`.
- Per-tool status tracking and overall progress.

## Supported Tools
- **Subfinder**: Subdomain enumeration.
- **HTTPX**: Live host probing and endpoint discovery.
- **Katana**: Web crawling and endpoint discovery.
- **Naabu**: Fast port scanning.

## Environment Variables
- `GRAPH_DB_URL`: Base URL for the `graph_db` service (default: `http://localhost:8001/api/v1`).
- `DOCKER_SOCKET`: Path to the Docker socket (default: `unix:///var/run/docker.sock`).
- `TOOL_TIMEOUT`: Timeout in seconds for each tool (default: `300`).

## API Usage

### 1. Start Reconnaissance
```bash
curl -X POST http://localhost:8002/api/v1/recon/start \
  -H "Content-Type: application/json" \
  -d '{
    "program_id": "YOUR_PROGRAM_ID",
    "domains": ["example.com", "test.com"]
  }'
```

### 2. Check Session Status
```bash
curl http://localhost:8002/api/v1/recon/{session_id}/status
```

### 3. Get Combined Results
```bash
curl http://localhost:8002/api/v1/recon/{session_id}/results
```

## Running Tests
```bash
cd wraith/recon_orchestrator
pip install -r requirements.txt
PYTHONPATH=. pytest
```
