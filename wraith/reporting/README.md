# Wraith — Phase 9: Reporting Module

The Reporting Service assembles data from `graph_db` and `active_exploit_runner` into professional vulnerability reports.

## Features
- Export to **Markdown** (for bug bounty submissions).
- Export to **PDF** (for formal deliverables).
- Graceful degradation for missing data (CVSS, Evidence, PoC).
- Multi-finding program reports with summary tables.

## API Endpoints

### 1. Single Finding Report
Returns a report for a specific finding in Markdown or PDF format.
- `GET /reports/{program_id}/findings/{finding_id}?format=markdown`
- `GET /reports/{program_id}/findings/{finding_id}?format=pdf`

**Example:**
```bash
curl http://localhost:8005/reports/prog_123/findings/find_456?format=markdown
```

### 2. Program-wide Report
Returns a combined report for all findings in a program, sorted by severity.
- `GET /reports/{program_id}?format=markdown`
- `GET /reports/{program_id}?format=pdf`

**Example:**
```bash
curl -o report.pdf http://localhost:8005/reports/prog_123?format=pdf
```

## Sample Report Section
```markdown
# Finding: SQLI in SQL injection in search

### 1. Title / Summary
SQLI in SQL injection in search

### 2. Vulnerability Type
CWE-89 - A03:2021-Injection

### 3. Severity + CVSS Score
- Severity: High
- CVSS Score: 9.8 (Critical)
- CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

### 4. Affected Asset
Host: example.com | Endpoint: /api/search | Parameter: query
...
```

## Running Tests
```bash
cd wraith/reporting
pip install -r requirements.txt
PYTHONPATH=. pytest
```
