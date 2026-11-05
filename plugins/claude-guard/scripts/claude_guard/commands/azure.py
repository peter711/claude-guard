"""Azure CLI and Azure PowerShell rules: destructive calls, secret reads, credential env echo."""

from __future__ import annotations

import re
from typing import Callable

# `az <group> [<subgroup> ...] <verb>`: command words never start with "-", so
# the walk stops at the first option and cannot match option values.
AZ = r"(?<![\w/.-])az(?:\.cmd)?\s+"
AZ_PATH = r"(?:[a-z0-9][a-z0-9-]*\s+)"  # one command word
# Local CLI housekeeping that shares verbs such as `purge` or `remove`.
AZ_NOT_LOCAL = r"(?!(?:cache|extension|config|cloud|alias)\s)"
END = r"(?=\s|$)"

AZ_DESTRUCTIVE_RE = re.compile(
    AZ + AZ_NOT_LOCAL + AZ_PATH + r"{0,4}"
    r"(?:(?:delete(?:-batch|-instances)?|purge|remove)" + END +
    r"|role\s+assignment\s+create" + END +
    r"|role\s+definition\s+(?:create|update)" + END +
    r"|(?:sp|app)\s+credential\s+reset" + END +
    r"|app\s+(?:permission\s+(?:grant|admin-consent)|federated-credential\s+create)" + END +
    r"|keyvault\s+set-policy" + END +
    r"|account\s+subscription\s+cancel" + END + r")"
    r"|" + AZ + r"(?:group\s+)?deployment\s+(?:group\s+)?create\b[^\n;&|]*--mode[ =]complete\b"
    r"|" + AZ + r"stack\s+(?:group|sub|mg)\s+create\b[^\n;&|]*--action-on-unmanage[ =]delete\w*"
    r"|" + AZ + r"backup\s+protection\s+disable\b[^\n;&|]*--delete-backup-data\b"
    r"|" + AZ + r"rest\b[^\n;&|]*(?:--method|-m)[ =]delete\b",
    re.IGNORECASE,
)
AZ_SECRET_READ_RE = re.compile(
    AZ + AZ_PATH + r"{0,4}"
    r"(?:keyvault\s+(?:secret\s+(?:show|show-deleted|download|backup)"
    r"|key\s+(?:decrypt|backup|export)"
    r"|certificate\s+backup"
    r"|security-domain\s+download)" + END +
    r"|account\s+get-access-token" + END +
    r"|acr\s+(?:credential\s+(?:show|renew)|token\s+(?:create|credential\s+generate))" + END +
    r"|storage\s+account\s+(?:keys\s+(?:list|renew)|show-connection-string)" + END +
    r"|keys\s+(?:list|renew|regenerate)" + END +
    r"|(?:list-keys|regenerate-keys?|list-connection-strings|list-secrets|list-credentials"
    r"|list-publishing-(?:credentials|profiles)|get-shared-keys|generate-sas|grant-access"
    r"|show-secret)" + END +
    r"|(?:admin|query)-key\s+(?:show|list|renew)" + END +
    r"|(?:signalr|webpubsub|eventgrid\s+(?:topic|domain))\s+key\s+(?:list|renew)" + END +
    r"|connection-string\s+show" + END +
    r"|appconfig\s+credential\s+(?:list|regenerate)" + END +
    r"|(?:sp\s+create-for-rbac|(?:sp|app)\s+credential\s+reset)" + END +
    r"|monitor\s+app-insights\s+api-key\s+create" + END +
    r"|(?:webapp|functionapp|logicapp|staticwebapp)\s+(?:config\s+)?(?:appsettings|connection-string)\s+list" + END +
    r"|staticwebapp\s+secrets\s+list" + END +
    r"|containerapp\s+(?:job\s+)?secret\s+show" + END +
    r"|config\s+get(?:\s+(?:storage|batch))?\s*(?:$|[;&|])" +
    r")"
    r"|" + AZ + r"acr\s+login\b[^\n;&|]*(?:--expose-token|\s-t)" + END +
    r"|" + AZ + r"containerapp\s+(?:job\s+)?secret\s+list\b[^\n;&|]*--show-values\b"
    r"|" + AZ + r"aks\s+get-credentials\b[^\n;&|]*(?:--admin|\s-a|--file[ =]-|\s-f[ =]?-)" + END +
    r"|" + AZ + r"rest\b[^\n;&|]*(?:/list(?:keys|secrets|connectionstrings|credentials|accountsas"
    r"|servicesas|publishingcredentials|adminkeys|querykeys)\b|/regeneratekey|vault\.azure\.net)",
    re.IGNORECASE,
)

# Az PowerShell. Local context/environment cmdlets stay allowed.
PS_DESTRUCTIVE_RE = re.compile(
    r"(?<![\w-])(?:Remove-Az(?!Context\b|Environment\b|Default\b)[A-Za-z]+"
    r"|New-AzRoleAssignment|(?:New|Set)-AzRoleDefinition|Set-AzKeyVaultAccessPolicy"
    r"|New-AzResourceGroupDeployment\b[^\n;&|]*-Mode\s+Complete\b"
    r"|Invoke-AzRestMethod\b[^\n;&|]*-Method\s+Delete\b)(?![\w-])",
    re.IGNORECASE,
)
PS_SECRET_READ_RE = re.compile(
    r"(?<![\w-])(?:Get-AzKeyVaultSecret\b[^\n;&|]*-AsPlainText\b"
    r"|Backup-AzKeyVault(?:Secret|Key|Certificate)"
    r"|Get-AzAccessToken"
    r"|(?:Get|New)-Az(?:StorageAccountKey|CosmosDBAccountKey|ServiceBusKey|EventHubKey"
    r"|RedisCacheKey|CognitiveServicesAccountKey|SearchAdminKey|SearchQueryKey|BatchAccountKey"
    r"|ContainerRegistryCredential|WebAppPublishingProfile|FunctionAppSetting"
    r"|ApiManagementSubscriptionKey|SignalRKey|IotHubKey)"
    r"|New-AzStorage\w*SASToken|New-AzADSpCredential|New-AzADAppCredential|Grant-Az(?:Disk|Snapshot)Access"
    r"|ConvertFrom-SecureString\b[^\n;&|]*-AsPlainText\b"
    r"|Invoke-AzRestMethod\b[^\n;&|]*(?:/list(?:keys|secrets|connectionstrings|credentials)\b"
    r"|vault\.azure\.net))(?![\w-])",
    re.IGNORECASE,
)

# Names matched generically: AZURE_CLIENT_SECRET, AZURE_PASSWORD, AZURE_STORAGE_KEY,
# AZURE_STORAGE_CONNECTION_STRING, AZURE_DEVOPS_EXT_PAT, ARM_CLIENT_SECRET, ARM_ACCESS_KEY, ...
# Not matched (not secret): *_CLIENT_ID, *_TENANT_ID, *_SUBSCRIPTION_ID, *_USERNAME, *_CLIENT_CERTIFICATE_PATH.
SECRET_ENV = r"\b(?:AZURE|ARM)_[A-Z0-9_]*(?:SECRET|PASSWORD|_KEY|_TOKEN|CONNECTION_STRING|_PAT)\b"
AZURE_CREDENTIAL_ECHO_RE = re.compile(
    r"(?<![\w/.$-])(?:printenv|env|echo|export\s+-p)\b[^\n;&]*" + SECRET_ENV +
    r"|\$\{?env:" + SECRET_ENV + r"\}?(?!\s*=(?!=))"
    r"|(?<![\w-])(?:Get-ChildItem|Get-Item|Get-Content|gci|gi|dir|ls)\s+(?:-Path\s+)?['\"]?env:" + SECRET_ENV +
    r"|GetEnvironmentVariable\(\s*['\"]" + SECRET_ENV,
    re.IGNORECASE,
)

RULES: tuple[tuple[Callable[[str], object], str], ...] = (
    (AZ_DESTRUCTIVE_RE.search, "destructive Azure CLI command"),
    (PS_DESTRUCTIVE_RE.search, "destructive Azure PowerShell command"),
    (AZ_SECRET_READ_RE.search, "Azure secret read"),
    (PS_SECRET_READ_RE.search, "Azure secret read"),
    (AZURE_CREDENTIAL_ECHO_RE.search, "credential echo or dynamic credential read"),
)
