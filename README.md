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
/plugin install agent-guard@claude-guard-marketplace
```

Reload plugins, then run `/hooks` to confirm the `PreToolUse` hook is listed.

To update or remove:

```bash
claude plugin marketplace update claude-guard-marketplace
claude plugin uninstall agent-guard@claude-guard-marketplace
```

> **Upgrading from 0.3.x:** the plugin was renamed from `claude-guard` to `agent-guard` (names starting with `claude-` are reserved). Run `claude plugin uninstall claude-guard@claude-guard-marketplace`, then install `agent-guard` as above.

## What gets blocked

| Example | Result |
|---|---|
| `cat .env`, `Read: .env.local`, `Grep` on `.env` | Deny |
| `cat ~/.ssh/id_ed25519`, `cat ~/.aws/credentials` | Deny |
| `rm -rf build`, `sudo ...`, `git push --force` | Deny |
| `aws s3 rm ...`, `aws ec2 terminate-instances ...`, `aws iam create-access-key` | Deny |
| `aws secretsmanager get-secret-value`, `printenv AWS_SECRET_ACCESS_KEY`, `vault read aws/creds/...` | Deny |
| `az group delete ...`, `az keyvault purge ...`, `Remove-AzResourceGroup ...`, `az role assignment create ...` | Deny |
| `az keyvault secret show ...`, `az storage account keys list ...`, `Get-AzAccessToken`, `printenv AZURE_CLIENT_SECRET` | Deny |
| `cat .env.example`, `git status`, `aws ec2 describe-instances`, `aws s3 ls`, `az group list`, `az vm show ...` | Allow (normal permissions apply) |

Also blocked: `.npmrc`, `.pypirc`, `.netrc`, `.kube/config`, `.aws/config`, AWS CLI/SSO caches, Azure CLI and Az PowerShell token caches and `.azure/config` (`azureProfile.json`, `clouds.config` and `.azure/config.json` stay allowed), `~/.vault-token`, GitHub CLI tokens, and `.pem`/`.p12`/`.pfx` files. Allowed templates: `.env.example`, `.env.sample`, `.env.template`, `.env.dist`.

The hook covers `Bash`, `PowerShell`, `Read`, `Write`, `Edit`, `NotebookEdit`, `Grep`, and `Glob`. It never logs tool inputs, and fails closed on malformed input or runtime errors.

## Limitations

- A shell can build paths dynamically, run other programs, or read secrets from environment variables, which bypasses this hook.
- AWS and Vault rules match CLI verbs and are best-effort; boto3, `bash -c`, aliases, or other tools bypass them.
- Azure rules match `az` and Az PowerShell verbs and are best-effort; `az rest` with other endpoints, Azure SDKs, `bash -c`, options placed before the command group, or other tools bypass them.
- MCP and custom tools are not inspected.
- Pattern matching may block harmless commands that mention `.env`.
- For stronger guarantees, use [sandboxing](https://code.claude.com/docs/en/sandboxing), deny permissions, and keep secrets out of the agent's environment.

## Development

```bash
python3 -m unittest discover -s tests -v
claude plugin validate .
```

Rules live in `plugins/claude-guard/scripts/claude_guard/` (`sensitive_paths.py`, `policy.py`, and `commands/` split into `core.py`, `aws.py`, `azure.py`, `vault.py`). New tools also need adding to the `matcher` in `hooks.json`.

See [CHANGELOG.md](CHANGELOG.md) for release notes.

## License

MIT
