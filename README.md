# Claude Guard

[Claude Code](https://code.claude.com/docs/en/plugins) `PreToolUse` hook that blocks direct access to secrets and a few risky shell commands before they run.

> **Scope:** best-effort protection against accidental secret reads and high-risk commands. Not a security boundary.

## Requirements

- Claude Code **v2.1.295+**
- `python3` 3.10+ on your `PATH`

## Install

In Claude Code:

```text
/plugin marketplace add peter711/claude-guard
/plugin install claude-guard@claude-guard-marketplace
```

Reload plugins, then run `/hooks` to confirm the `PreToolUse` hook is listed.

To update or remove:

```bash
claude plugin marketplace update claude-guard-marketplace
claude plugin uninstall claude-guard@claude-guard-marketplace
```

## What gets blocked

| Example | Result |
|---|---|
| `cat .env`, `Read: .env.local`, `Grep` on `.env` | Deny |
| `cat ~/.ssh/id_ed25519`, `cat ~/.aws/credentials` | Deny |
| `rm -rf build`, `sudo ...`, `git push --force` | Deny |
| `cat .env.example`, `git status` | Allow (normal permissions apply) |

Also blocked: `.npmrc`, `.pypirc`, `.netrc`, `.kube/config`, GitHub CLI tokens, and `.pem`/`.p12`/`.pfx` files. Allowed templates: `.env.example`, `.env.sample`, `.env.template`, `.env.dist`.

The hook covers `Bash`, `PowerShell`, `Read`, `Write`, `Edit`, `NotebookEdit`, `Grep`, and `Glob`. It never logs tool inputs, and fails closed on malformed input or runtime errors.

## Limitations

- A shell can build paths dynamically, run other programs, or read secrets from environment variables, which bypasses this hook.
- MCP and custom tools are not inspected.
- Pattern matching may block harmless commands that mention `.env`.
- For stronger guarantees, use [sandboxing](https://code.claude.com/docs/en/sandboxing), deny permissions, and keep secrets out of the agent's environment.

## Development

```bash
python3 -m unittest discover -s tests -v
claude plugin validate .
```

Rules live in `plugins/claude-guard/scripts/claude_guard/` (`sensitive_paths.py`, `commands.py`, `policy.py`). New tools also need adding to the `matcher` in `hooks.json`.

## License

MIT
