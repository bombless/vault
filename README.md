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

- **AES-256-GCM Encrypted Storage**: All profile JSON configuration values are encrypted at rest using AES-256-GCM authenticated encryption. Encryption keys are securely derived from the profile's password and a random salt using `scrypt`.
- **Session-based Key Isolation (Cross-Platform)**:
  - When switching profiles with `vault profile <name>`, the user verifies the profile password.
  - A 32-byte derived session key is generated and cached in a private session store (`/dev/shm` RAM tmpfs on Linux where available, or `%LOCALAPPDATA%\\vault-cli` on Windows) with `0600` permissions.
  - **The user's plaintext password is never stored**.
  - Subsequent `read` and `write` operations transparently decrypt and re-encrypt the active profile without re-prompting for passwords.
- **Protection for Inactive Profiles**:
  - Inactive profile files on disk are completely encrypted. Even if an unprivileged agent, untrusted script, or other processes running under the same OS user attempt to read `prod.json`, they will only observe ciphertext (`data`, `iv`, `tag`, and `salt`). Without the specific profile password or key, values cannot be decrypted.
  - On POSIX, directories are enforced with `chmod 0700` and files with `chmod 0600`; symlink profile files and files owned by another user are rejected.
- **Zero-OS-Privilege Overhead**:
  - Both Linux and Windows share the exact same user experience without requiring administrative privileges, UAC prompts, `sudo`, or `pkexec`.
  - Default data path is `~/.local/share/vault-cli` (or `%LOCALAPPDATA%\\vault-cli` on Windows); override with `VAULT_HOME`.

## Install the command

From this directory, run `npm link` (or `npm install -g .`) on the target machine. This registers the `vault` executable on PATH; on Windows npm creates a command shim. Verify with `vault --help`.

The bot integration invokes `vault` from PATH. Set `VAULT_HOME` consistently for a given OS account if you need a non-default data directory.
