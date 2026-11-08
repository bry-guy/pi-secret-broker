# pi-secret-broker

Role secrets for [pi](https://github.com/earendil-works/pi), resolved on the host and never shown to the agent.

- **Secret resolution** for [pi-mounts](https://github.com/bry-guy/pi-mounts): a sandboxed session's HTTP secrets
  (e.g. `GH_TOKEN`) become Gondolin placeholders that only work for the hosts the role lists.
- **`broker_run`**: runs a role's host actions (non-HTTP credentials: `tofu plan` with S3 state, `kubectl` against a
  tailnet API) with the role's secrets in a clean environment, and returns redacted output.

Roles and grants come from [pi-projects](https://github.com/bry-guy/pi-projects) (`docs/agent-roles.md`). Install both.

## Secret sources

In the signed grants file (`~/.pi/agent/pi-roles.json`, edited through `/project grant`), per role:

```json
"sources": {
  "infra/infra-developer": {
    "OP_SERVICE_ACCOUNT_TOKEN": "keychain:infra-developer",
    "INFRA_OP_VAULT": "value:infra-developer",
    "GH_TOKEN": "op://infra-developer/github-agent-token/credential"
  }
}
```

| Source | Meaning |
|---|---|
| `keychain:<service>` | macOS Keychain generic password, account `$USER` |
| `op://vault/item/field` | 1Password, read with the role's `OP_SERVICE_ACCOUNT_TOKEN` only. Never Bryan's desktop app. |
| `github-app:op://vault/item` | GitHub App installation token (1 hour), minted from the item's `app-id` and `private-key` fields. The App must be installed on one account. Cached until 15 minutes before expiry; pi-mounts re-resolves secrets every 30 minutes. |
| `env:NAME`, `file:path`, `value:text` | Host env var, file contents, literal |

## Broker actions

A role file (`<repo>/.pi/roles/<role>.json`, read from origin's default branch) declares them:

```json
"broker": {
  "tofu-plan": {
    "description": "tofu plan for a region",
    "run": ["mise", "exec", "--", "fnox", "exec", "--profile", "tofu", "--", "tofu", "-chdir={dir}", "plan", "-no-color"],
    "args": { "dir": "selfhost/regions/[a-z0-9-]+" },
    "env": ["OP_SERVICE_ACCOUNT_TOKEN", "INFRA_OP_VAULT"],
    "approve": "auto"
  }
}
```

- `run` is fixed argv. `{arg}` is filled only from `args`, and each value must fully match its regex.
- It runs in the checkout the agent names (`repos/<repo>` or `worktrees/<repo>/<branch>`, the role's own repo only),
  plus `cwd`.
- The environment is `PATH`, `HOME`, `USER`, `LANG`, `TMPDIR`, `SHELL` and the listed secrets. No SSH agent, no
  `OP_*`, no tokens from Bryan's shell.
- `approve: "ask"` confirms with Bryan first (forwarded to the TUI from background runs). With no one to ask, it's refused.
- Output is capped at 60 KB, secret values (6+ chars) are replaced by `[NAME]`, and every run is logged to
  `~/.pi/agent/pi-secret-broker/audit.jsonl`. Default timeout 15 minutes.

Limit: code in the checkout runs with the action's secrets (tofu modules, scripts). That fits the threat model
(agents making mistakes), not a hostile agent.

## Changes from pi-ez-secret-broker 0.2

Renamed. 1Password Connect handles, the HTTP request tool and the pi-chat runtime were removed: Gondolin injects HTTP
secrets itself, and roles replace the per-credential policy file.
