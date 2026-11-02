# Changelog

## v0.3.0 - 2026-11-02

Renamed to pi-secret-broker and rebuilt for pi-projects roles.

- Secret sources per role (`keychain:`, `op://` with the role's service-account token only, `env:`, `file:`, `value:`).
- `broker_run`: role host actions with fixed argv, validated args, clean env, redacted output and an audit log.
- Removed 1Password Connect handles, the HTTP request tool and the pi-chat broker runtime.

## v0.2.0 - 2026-05-25

Adds policy/approval/audit UX needed before real homelab use.

- Adds `/secret-broker approve <id>` for rules marked `requiresApproval`.
- Adds path+method rules with `path`, `pathPrefix`, `pathRegex`, and `requiresApproval`.
- Adds JSONL audit log for handle issuance, approval requests/grants, and brokered HTTP calls.

## v0.1.0 - 2026-05-25

Initial cut of `pi-ez-secret-broker`.

- Adds `/secret-broker init|new|bootstrap [--global|--project] [--force]` command to create config templates.
- Adds `/secret-broker status` command for host-side UX.
- Adds pi package manifest with one extension.
- Adds `secret_broker_request_credential` for short-lived credential handles.
- Adds `secret_broker_http_request` for host-mediated allowlisted HTTP(S) requests with policy-injected auth.
- Adds `secret_broker_status` for non-secret broker introspection.
- Supports 1Password Connect backend.
- Supports env backend for local testing.
- Avoids writing plaintext secrets to `/workspace/.secrets`.
