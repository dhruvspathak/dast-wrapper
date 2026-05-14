# Replay, Auth, And Authorization Validation

## Auth Engine

`AuthContext` is the only supported interface for authenticated replay and scanner sessions.

It supports:

- bearer headers
- cookies
- local storage
- session storage
- refresh token metadata
- browser storage state
- role and workspace boundaries
- expiry tracking

`AuthContextManager` persists and retrieves role-scoped contexts. Playwright stores isolated browser state per workspace, application, and role.

## Replay Engine

Replay is deterministic validation, not a scanner echo.

The replay engine produces:

- response status and body
- elapsed time
- response fingerprint
- body similarity
- ownership metadata deltas
- semantic JSON shape summary
- bounded diff excerpts

Use `REPLAY_ALLOWED_HOSTS` in production to constrain replay scope.

## Authorization Engine

The authorization engine validates:

- horizontal privilege escalation
- vertical privilege escalation
- BOLA/IDOR
- token swapping
- identifier mutation
- object ownership deltas

Automatically detected identifiers include `user_id`, `plan_id`, `report_id`, `org_id`, `activity_id`, `tenant_id`, and `workspace_id`.

AI triage consumes the validation evidence after replay and authorization checks. It must not directly trust scanner findings.
