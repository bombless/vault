# vault CLI (prototype)

Standalone Node.js CLI for profile-scoped local JSON settings. Requires Node.js 18+ and no third-party dependencies.

## Commands

```sh
node bin/vault.js profile init agent
node bin/vault.js profile agent
node bin/vault.js write MODEL qwen3.7-max
node bin/vault.js write API_KEY       # hidden interactive input
node bin/vault.js read MODEL
node bin/vault.js profile list
```

After creating a profile, switch to it with its password before reading or writing. `write KEY VALUE` is convenient but can expose VALUE in shell history or process listings; prefer `write KEY` for secrets.

## Storage and security boundary

- JSON files contain plaintext values. On POSIX, directories are chmod 0700 and files 0600; symlink profile files and files owned by another user are rejected.
- Default data path is `~/.local/share/vault-cli` (or `%LOCALAPPDATA%\\vault-cli` on Windows); override with `VAULT_HOME`.
- The profile password is a CLI switching guard, **not encryption**. A user who can read the JSON file can bypass the CLI or modify its source. Do not rely on the password to defend secrets from arbitrary code running as the same OS user.
- To protect `dev`/`prod` from a coding agent, run the agent as a separate unprivileged OS account and keep those profile files owned by a different account with restrictive permissions. Do not give the agent sudo, root, Docker socket access, or production deployment credentials.
- The first prototype is intended for POSIX account isolation. Windows ACLs must be configured and verified separately; chmod-style mode bits do not provide equivalent Windows isolation.

## Install the command

From this directory, run `npm link` (or `npm install -g .`) on the target machine. This registers the `vault` executable on PATH; on Windows npm creates a command shim. Verify with `vault --help`.

The bot integration invokes `vault` from PATH. Set `VAULT_HOME` consistently for a given OS account if you need a non-default data directory.
