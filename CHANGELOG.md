# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
