# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2026-11-05

### Added

- Deny rule for whole-environment dumps (`env`, `printenv`, `export`/`export -p`, bare `set`, `declare`/`typeset -p`/`-x`, `ps eww`/`ps e`, PowerShell `Env:` listings and `GetEnvironmentVariables()`), including one level of `bash -c`.
- `printenv` of secret-looking variable names is denied; `printenv HOME` and `printenv PATH` stay allowed.
- `/proc/<pid>/environ` is a sensitive path, blocked for `Read` and `Grep` as well as shell commands.

### Changed

- New `environment` rule module, registered last so specific AWS, Azure and Vault reasons win.

## [0.5.0] - 2026-11-05

### Added

- Deny rules for destructive Azure CLI commands (`delete`/`purge`/`remove` verbs, role assignment and definition changes, credential resets, Key Vault access policies, complete-mode deployments, `az stack ... --action-on-unmanage delete*`, `az rest --method delete`).
- Deny rules for destructive Azure PowerShell commands (`Remove-Az*` except local context cmdlets, role assignments, complete-mode deployments, `Invoke-AzRestMethod -Method Delete`).
- Deny rules for Azure secret reads in `az` and PowerShell (Key Vault secrets and keys, access tokens, storage/Cosmos DB/Service Bus/Redis and similar keys, connection strings, publishing credentials, app settings, SAS tokens, `aks get-credentials --admin`).
- Deny rule for echoing `AZURE_*` and `ARM_*` secret environment variables (`printenv`, `echo`, `$env:`, `Get-ChildItem Env:`).
- New sensitive paths under `.azure`: `config` (but not `config.json`), MSAL token and HTTP caches, `service_principal_entries.json`, `accessTokens.json`, and Az PowerShell token caches.

### Changed

- Vault credential rule also matches `static-creds/` (for example `vault read azure/static-creds/<role>`).
- New `azure` module under `claude_guard/commands/`, registered between `aws` and `vault`.

## [0.4.0] - 2026-11-05

### Added

- Plugin author metadata in `plugin.json`.

### Changed

- **BREAKING:** plugin renamed from `claude-guard` to `agent-guard`, because third-party plugin names starting with `claude-` are reserved. The marketplace name (`claude-guard-marketplace`), GitHub repository and plugin directory are unchanged. Existing users must uninstall the old plugin and install the new one:

  ```bash
  claude plugin uninstall claude-guard@claude-guard-marketplace
  claude plugin marketplace update claude-guard-marketplace
  claude plugin install agent-guard@claude-guard-marketplace
  ```

## [0.3.0] - 2026-11-05

### Added

- Deny rules for destructive AWS CLI commands (delete/terminate/purge/remove/detach/deregister verbs, `create-access-key`, policy changes, `s3 rm`/`rb`, `s3 sync --delete`).
- Deny rules for AWS secret reads (Secrets Manager, decrypted SSM parameters, KMS decrypt, STS session tokens, `aws configure get` of credentials).
- Deny rules for credential echo (`printenv`/`echo` of AWS credential variables) and Vault credential reads (`vault read|write .../creds/` and `.../sts/`, `vault print token`).
- New sensitive paths: `.vault-token`, `.aws/config`, `.aws/cli/cache`, `.aws/sso/cache`.

### Changed

- Command rules are split into per-domain modules under `claude_guard/commands/` (`core`, `aws`, `vault`). The public API (`destructive_command`) and deny behaviour are unchanged.
- The README links to this changelog.

## [0.2.0] - 2026-11-04

### Added

- Policy checks and command detection split into a `claude_guard` package (`policy`, `commands`, `sensitive_paths`).

### Changed

- Trimmed the README to user-facing essentials and clarified install instructions.

## [0.1.0] - 2026-11-04

### Added

- Initial release: `PreToolUse` hook that blocks reads of common secret files and risky shell commands.
