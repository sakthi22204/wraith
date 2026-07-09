# Wraith — Phase 8: Confidence & False-Positive Reduction (graph_db)

The graph database now supports an advanced finding lifecycle with confidence scoring, corroboration tracking, and false-positive pattern management.

## Authentication
Administrative and destructive endpoints require a Bearer token.
Set the `ADMIN_API_TOKEN` environment variable.

- `DELETE /api/v1/programs/{id}`: Requires token.

## Finding Statuses
1.  **UNCONFIRMED:** Initial state for low-confidence findings (< 0.7).
2.  **AI_VALIDATED:** Initial state for high-confidence findings (>= 0.7).
3.  **CORROBORATED:** Transitioned to when 2+ sources confirm the finding.
4.  **HUMAN_CONFIRMED:** Terminal state set by a person.
5.  **FALSE_POSITIVE:** Terminal state set by a person; creates an FP pattern.
6.  **DUPLICATE:** Merged into another finding.

## Human Review Queue
New API endpoints facilitate human-in-the-loop verification:
- `GET /programs/{id}/findings/review-queue`: Fetches findings needing review, sorted by severity (DESC) and confidence (ASC).
- `POST /findings/{id}/review`: Mark a finding as confirmed or a false positive.
- `POST /findings/{id}/corroborate`: Add a corroborating source.

## False Positive Patterns
Marking a finding as `FALSE_POSITIVE` automatically creates a `FalsePositivePattern` node. Future findings matching the same `vuln_type` and `endpoint_pattern` will have their confidence scores automatically penalized.
