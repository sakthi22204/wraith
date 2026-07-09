# Wraith — Phase 3: Kali Sandbox + MCP Tool Wrapping

This service provides a sandboxed environment for running heavy security tools (Nmap, Nuclei, SQLMap, Hydra, Metasploit) exposed as Model Context Protocol (MCP) servers.

## Access Control
Dangerous tools (`run_hydra`, `run_msf_module`) require server-side caller validation.
The caller must provide an `X-Wraith-Caller` header matching an authorized service name (default: `active_exploit_runner`).

## ⚠️ Safety Warning
This phase is designed for **LOCAL TEST TARGETS ONLY**. The tools are configured to run within a controlled environment against deliberately vulnerable targets like OWASP Juice Shop. **Never** use these tools against real external targets until Phase 5 guardrails are implemented.

## Features
- Kali Linux based sandbox.
- MCP servers for Nmap, Nuclei, SQLMap, Hydra, and Metasploit.
- Strict input validation to prevent command injection.
- Structured Pydantic results for all tools.
- Enforced timeouts and resource limits.

## Tools and Signatures

### Nmap Server
- `run_nmap_scan(target: str, ports: str, scan_type: NmapScanType)`
  - `target`: Hostname or IP.
  - `ports`: Port range (e.g., "1-1000").
  - `scan_type`: Enum (SERVICE_DETECTION, DEFAULT_SCRIPTS, AGGRESSIVE, FULL_PORT).

### Nuclei Server
- `run_nuclei_scan(target: str, category: NucleiTemplateCategory)`
  - `target`: URL or hostname.
  - `category`: Enum (cves, exposures, vulnerabilities, misconfiguration).

### SQLMap Server
- `run_sqlmap(url: str, param: str, method: SQLMapMethod, data: str)`
  - `url`: Target URL.
  - `param`: Parameter to test.
  - `method`: GET or POST.
  - `data`: POST data.

### Hydra Server
- `run_hydra(target: str, service: str, user: str, pass_list: str)`
  - `target`: Target host.
  - `service`: Service (e.g., "http-get", "ssh").
  - `user`: Username.
  - `pass_list`: Path to bundled wordlist (must be in `/app/wordlists/`).

### Metasploit Server
- `list_modules(search: str)`
  - `search`: Search query for modules.
- `run_module(module: str, target: str, options: dict)`
  - `module`: Full module name.
  - `target`: Target host (RHOSTS).
  - `options`: Dictionary of module options.

## Running Tests
```bash
cd wraith/kali_sandbox
pip3 install -r requirements.txt --break-system-packages
PYTHONPATH=. pytest
```
