# Wraith — Phase 7: Frontend Control Panel

Interactive control panel for the Wraith autonomous bug-bounty pipeline. The browser UI is a thin, read-mostly view layer; **the backend services remain the security authority** for scope, killswitch, rate limiting, and audit.

## Architecture

- **Framework**: Next.js 15 (App Router), React 19, Tailwind 4.
- **Visualization**: `react-force-graph-2d` for the attack surface graph; SSE for the live agent activity feed.
- The browser talks to backend services in two ways:
  1. **Direct** — open read endpoints (graph, recon status, agent status, execution history, audit, scope, assessment) are fetched by the client from `NEXT_PUBLIC_*_URL` service URLs.
  2. **Server-side proxy routes** — any operation that requires the admin token goes through a Next.js route handler so `ADMIN_API_TOKEN` is never exposed to the browser.

## Server-side proxy routes

| Route | Backend target | Purpose |
|---|---|---|
| `DELETE /api/investigations/[id]` | `graph_api` `DELETE /investigations/{id}?confirm=true` | Delete an investigation (admin token) |
| `GET /api/reports` | `reporting` `GET /reports/{id}?format=…` | Report download (admin token) |
| `GET /api/killswitch` | `active_exploit_runner` `GET /exploit/killswitch/status` | Killswitch status |
| `POST /api/killswitch` | `active_exploit_runner` `POST /exploit/killswitch/activate\|deactivate` | Killswitch control |

The killswitch proxy accepts **only** the fixed actions `activate` / `deactivate`; it cannot be pointed at arbitrary backend endpoints.

## Security boundary

- `ADMIN_API_TOKEN` is used only in Next.js route handlers (server-side). It is never sent to the browser, never embedded in the client bundle, and never sent in browser network requests.
- Killswitch activation/deactivation requires the admin token server-side; the browser only ever calls the local proxy.
- RoE scope display is **read-only**. Scope enforcement (deny-rules-win) happens only in the backend executor.
- The Docker Broker is never reachable from the browser; recon/exploit execution flows through backend services.

## Pages

- `/` — investigation list, create, delete.
- `/investigations/[id]` — dashboard: live recon/agent phases, graph stats, severity distribution, live terminal, review queue, autonomous execution history, rules of engagement, report export.
- `/investigations/[id]/findings` — findings list grouped by asset.
- `/investigations/[id]/graph` — interactive attack surface graph.
- `/investigations/[id]/assessment` — risk score, validation plan, prioritized targets, CVEs.
- `/investigations/[id]/agent` and `/agent/[sessionId]` — agent session history and live SSE reasoning feed.
- `/investigations/[id]/recon-sessions` — recon history with live tool timeline and logs.
- `/investigations/[id]/review` — human review of low-confidence findings (confirm / false positive).
- `/investigations/[id]/exploitation` — autonomous exploit executions (queued/running/terminal status) and the immutable per-investigation audit trail from `active_exploit_runner`. Execution is gated by scope, killswitch, aggressiveness, rate limits, and the runner's deterministic checks; it is not approved per action in the browser.

## Killswitch behavior

- A global killswitch indicator is shown in the header on every page.
- **Active** is shown in pulsing red; **inactive** in green; unreachable backend shows an amber unknown state.
- Activate/deactivate require an explicit confirmation in the modal; status is re-fetched after every mutation; backend errors are surfaced instead of assuming success.
- When active, the backend executor blocks all exploitation and records `BLOCKED / Killswitch active` in the audit trail.

## Getting Started

### Prerequisites
- Node.js 18+
- Active backend services (`graph_api`, `recon_orchestrator`, `exploit_agent`, `active_exploit_runner`, `reporting`, `assessment_service`)
- **Build-time network access**: Required for `next/font/google` to fetch Geist and JetBrains Mono from fonts.googleapis.com.

### Environment Variables
```bash
NEXT_PUBLIC_GRAPH_DB_URL=http://localhost:8001/api/v1
NEXT_PUBLIC_AGENT_URL=http://localhost:8003/api/v1
NEXT_PUBLIC_RECON_URL=http://localhost:8002/api/v1
NEXT_PUBLIC_EXPLOIT_RUNNER_URL=http://localhost:8004/api/v1
NEXT_PUBLIC_REPORTING_URL=http://localhost:8006/api/v1
NEXT_PUBLIC_ASSESSMENT_URL=http://localhost:8007/api/v1
ADMIN_API_TOKEN=dev-token-change-me
GRAPH_DB_URL=http://graph_api:8001/api/v1
EXPLOIT_RUNNER_URL=http://active_exploit_runner:8004/api/v1
REPORTING_URL=http://reporting:8006/api/v1
```

### Development
```bash
npm install
npm run dev
```
The UI will be available at `http://localhost:3000`.

### Testing
```bash
npm test
```
Run with `NODE_ENV=test` when executing tests inside the production image, otherwise React loads its production build and the jsdom `act` helper is unavailable.

### Build
```bash
npm run build
```
