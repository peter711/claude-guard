# Claude Guard

Installable [Claude Code](https://code.claude.com/docs/en/plugins) `PreToolUse` security hook, distributed as a GitHub plugin marketplace.

> **Scope:** best-effort protection against accidental/direct secret reads and a few high-risk commands. Not a complete security boundary, malware scanner, or guarantee against deliberate exfiltration.

## Requirements

- Claude Code **v2.1.295+** (for `onFailure: "block"`; newer releases recommended)
- `python3` on your `PATH` (Python 3.10+)
- Local CLI / supported local Claude Code environment with plugin hooks enabled

## Install from GitHub

1. Publish this entire folder as a GitHub repository named `claude-guard`.
2. Replace `YOUR_GITHUB_USERNAME` in these commands with your account or organization.
3. In the **Claude Code interactive prompt** (not a normal shell), run:

```text
/plugin marketplace add YOUR_GITHUB_USERNAME/claude-guard
/plugin install claude-guard@claude-guard-marketplace
```

Install at user scope for every local project, or select project scope in the plugin UI. Restart Claude Code (or reload plugins if available), then run `/hooks` to verify the installed `PreToolUse` hook appears.

From your terminal, the equivalent is:

```bash
claude plugin marketplace add YOUR_GITHUB_USERNAME/claude-guard
claude plugin install claude-guard@claude-guard-marketplace
```

You can also load this plugin locally without publishing:

```bash
claude --plugin-dir ./plugins/claude-guard
```

> If you use an organization-managed Claude Code instance, your administrator may need to allow third-party marketplaces/plugins.

## What gets blocked?

| Example tool call | Default |
|---|---|
| `Bash: cat .env` | DENY |
| `Bash: head api/.env.production` | DENY |
| `Bash: cat ~/.ssh/id_ed25519` | DENY |
| `Bash: cat ~/.aws/credentials` | DENY |
| `Read: /work/.env.local` | DENY |
| `Grep: path=/work/.env, pattern=API_KEY` | DENY |
| `Bash: rm -rf build` | DENY |
| `Bash: sudo ...` | DENY |
| `Bash: git push --force origin main` | DENY |
| `Bash: cat .env.example` | ALLOW (normal Claude permissions still apply) |
| `Bash: git status`, `python3 -m unittest` | ALLOW (normal permissions apply) |

The hook handles direct paths/references for `Bash`, `PowerShell`, `Read`, `Write`, `Edit`, `NotebookEdit`, `Grep`, and `Glob`. It also blocks direct references to `.npmrc`, `.pypirc`, `.netrc`, SSH private keys, `.aws/credentials`, `.kube/config`, GitHub CLI token config, common credential files, and `.pem/.p12/.pfx` files. It permits `.env.example`, `.env.sample`, `.env.template`, and `.env.dist`.

## How it works

`plugins/claude-guard/hooks/hooks.json` registers `PreToolUse`, with `onFailure: "block"`. Claude Code invokes `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/guard.py` before each matched tool call. The hook parses input JSON from stdin and exits:

- `0` to continue through the normal Claude Code permission flow
- `2` to deny and show a short reason on stderr

Malformed hook input or script/runtime failures **fail closed** on recent Claude Code versions that support `onFailure: "block"`.

The script does not log tool inputs or secret contents. You can adjust lists and patterns in `plugins/claude-guard/scripts/guard.py`, then run tests and release an updated plugin version.

## Local tests

```bash
python3 -m unittest discover -s tests -v
claude plugin validate ./plugins/claude-guard
claude plugin validate .
```

The `claude plugin validate` commands require Claude Code to be installed. Tests do not execute the shell commands being inspected.

Manually verify with a test project that **contains no real secrets**: ask Claude Code to run `cat .env`; the guard should reject the tool call before execution. Check `/hooks` if it does not.

## Publish to GitHub

Create an empty repo named `claude-guard` under your account, then run from this directory:

```bash
git init
git add .
git commit -m "Initial release of Claude Guard"
git branch -M main
git remote add origin https://github.com/YOUR_GITHUB_USERNAME/claude-guard.git
git push -u origin main
```

Do not commit real `.env` files, keys, tokens, or local secrets. Check the staged diff before publishing.

## Update / uninstall

In Claude Code, use `/plugin` to manage installed plugins and marketplaces. In a terminal:

```bash
claude plugin marketplace update claude-guard-marketplace
claude plugin uninstall claude-guard@claude-guard-marketplace
```

## Limitations / threat model

- **Not a security boundary.** This only inspects the immediate input of matched Claude Code tools, using conservative text/path patterns. A shell can construct paths dynamically, execute other programs, use indirect file reads, or retrieve secrets from process environment variables. These can bypass this hook.
- It doesn't intercept arbitrary MCP/custom tools, network services, or access by other processes. A broad `Grep` or a script can read sensitive files indirectly.
- Pattern matching can block harmless commands mentioning `.env` or similar names; this is intentional for a simple conservative first version.
- Installed plugins can be disabled, changed, or superseded by environment/managed policy settings. An agent with access to the hook's source/config or the machine itself can potentially weaken its protection.
- For stronger guarantees: don't expose secrets to the agent's runtime. Restrict secret file access at the OS/container level, enable [Claude Code sandboxing](https://code.claude.com/docs/en/sandboxing), use deny permissions and managed policy, restrict network access, and isolate sensitive credentials.
- Review plugin source before installation; do not install untrusted GitHub plugins.

## Official docs

- [Hooks reference](https://code.claude.com/docs/en/hooks)
- [Plugin marketplaces](https://code.claude.com/docs/en/plugin-marketplaces)
- [Permissions](https://code.claude.com/docs/en/permissions)

## License

MIT
