#Requires -Version 7.2
<#
.SYNOPSIS
  Deploy the N2 License Server to your Coolify instance on n2.systems.

.DESCRIPTION
  Reads secrets from $env:USERPROFILE\.devin\n2-deploy-secrets.json,
  creates the Cloudflare DNS record, configures the Coolify application,
  and triggers a deployment. The secrets file is securely overwritten
  after the run.

.EXAMPLE
  .\deploy-to-coolify.ps1
#>
param(
    [string]$SecretsPath = "$env:USERPROFILE\.devin\n2-deploy-secrets.json"
)

$ErrorActionPreference = "Stop"

function Write-Section($msg) {
    Write-Host "`n=== $msg ===" -ForegroundColor Cyan
}

function Remove-SecretsFile($path) {
    if (Test-Path $path) {
        $bytes = [byte[]]::new((Get-Item $path).Length)
        [System.IO.File]::WriteAllBytes($path, $bytes)
        Remove-Item $path -Force
    }
}

if (-not (Test-Path $SecretsPath)) {
    throw "Secrets file not found: $SecretsPath"
}

try {
    $secrets = Get-Content $SecretsPath | ConvertFrom-Json
} finally {
    # Keep file around until we finish, then overwrite+delete at the end.
}

$required = @(
    "cloudflare_api_token",
    "coolify_api_token",
    "coolify_url",
    "domain",
    "admin_password",
    "repo_owner",
    "repo_name",
    "branch"
)
foreach ($r in $required) {
    if (-not $secrets.$r) {
        throw "Missing secret: $r"
    }
}

$domain = $secrets.domain
$adminPassword = $secrets.admin_password
$repoOwner = $secrets.repo_owner
$repoName = $secrets.repo_name
$branch = $secrets.branch
$repoUrl = "https://github.com/$repoOwner/$repoName.git"

$secretKey = if ($secrets.secret_key) { $secrets.secret_key } else {
    $bytes = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    [Convert]::ToBase64String($bytes)
}

# --------------------------------------------------------------------------- #
# 1. Generate admin password hash
# --------------------------------------------------------------------------- #
Write-Section "Generating admin password hash"
$adminPasswordHash = python -c "import bcrypt; print(bcrypt.hashpw(b'$adminPassword', bcrypt.gensalt(rounds=12)).decode())"
if (-not $adminPasswordHash) {
    throw "Failed to generate bcrypt hash. Is bcrypt installed?"
}

# --------------------------------------------------------------------------- #
# 2. Cloudflare DNS record
# --------------------------------------------------------------------------- #
Write-Section "Configuring Cloudflare DNS"
$cfHeaders = @{
    Authorization  = "Bearer $($secrets.cloudflare_api_token)"
    "Content-Type" = "application/json"
}

$zones = Invoke-RestMethod -Uri "https://api.cloudflare.com/client/v4/zones?name=n2.systems" -Headers $cfHeaders
$zoneId = $zones.result[0].id
if (-not $zoneId) {
    throw "Could not find n2.systems zone in Cloudflare"
}

$existing = Invoke-RestMethod -Uri "https://api.cloudflare.com/client/v4/zones/$zoneId/dns_records?type=A&name=$domain" -Headers $cfHeaders
if ($existing.result.Count -eq 0) {
    $recordName = if ($domain -eq "n2.systems") { "@" } else { $domain -replace '\.n2\.systems$', '' }
    $body = @{
        type    = "A"
        name    = $recordName
        content = "46.4.65.32"
        ttl     = 120
        proxied = $false
    } | ConvertTo-Json
    Invoke-RestMethod -Uri "https://api.cloudflare.com/client/v4/zones/$zoneId/dns_records" -Method Post -Headers $cfHeaders -Body $body | Out-Null
    Write-Host "Created A record $domain -> 46.4.65.32" -ForegroundColor Green
} else {
    Write-Host "A record already exists" -ForegroundColor Green
}

# --------------------------------------------------------------------------- #
# 3. Coolify application
# --------------------------------------------------------------------------- #
Write-Section "Configuring Coolify"
$coolifyBase = ($secrets.coolify_url -replace '/$', '') + "/api/v1"
$ch = @{
    Authorization  = "Bearer $($secrets.coolify_api_token)"
    "Content-Type" = "application/json"
}

$servers = Invoke-RestMethod -Uri "$coolifyBase/servers" -Headers $ch
$serverUuid = $servers[0].uuid
if (-not $serverUuid) { throw "No Coolify server found" }
Write-Host "Server UUID: $serverUuid"

$destinations = Invoke-RestMethod -Uri "$coolifyBase/destinations" -Headers $ch
$destination = $destinations | Where-Object { $_.server_uuid -eq $serverUuid } | Select-Object -First 1
if (-not $destination) {
    # Fall back to any destination
    $destination = $destinations | Select-Object -First 1
}
if (-not $destination) { throw "No Coolify destination found" }
Write-Host "Destination UUID: $($destination.uuid)"

$projects = Invoke-RestMethod -Uri "$coolifyBase/projects" -Headers $ch
$project = $projects | Where-Object { $_.name -eq "license-server" } | Select-Object -First 1
if (-not $project) {
    $body = @{name = "license-server"; description = "N2 License Server"} | ConvertTo-Json
    $project = Invoke-RestMethod -Uri "$coolifyBase/projects" -Method Post -Headers $ch -Body $body
    Write-Host "Created project $($project.uuid)" -ForegroundColor Green
} else {
    Write-Host "Using existing project $($project.uuid)"
}

$envs = Invoke-RestMethod -Uri "$coolifyBase/projects/$($project.uuid)/environments" -Headers $ch
$environment = $envs | Where-Object { $_.name -eq "production" } | Select-Object -First 1
if (-not $environment) { throw "No production environment found in project" }
Write-Host "Environment: $($environment.name) / $($environment.uuid)"

$apps = Invoke-RestMethod -Uri "$coolifyBase/applications" -Headers $ch
$app = $apps | Where-Object { $_.name -eq "N2 License Server" } | Select-Object -First 1

$appBody = @{
    project_uuid           = $project.uuid
    server_uuid            = $serverUuid
    destination_uuid       = $destination.uuid
    environment_uuid       = $environment.uuid
    environment_name       = $environment.name
    git_repository         = $repoUrl
    git_branch             = $branch
    build_pack             = "dockercompose"
    name                   = "N2 License Server"
    description            = "License + update server for ThaliaMed"
    domains                = "https://$domain"
    ports_exposes          = "8000"
    is_auto_deploy_enabled = $true
    is_force_https_enabled = $true
    health_check_enabled   = $true
    health_check_path      = "/admin/health"
    health_check_port      = "8000"
    health_check_method    = "GET"
} | ConvertTo-Json -Depth 10

if (-not $app) {
    $app = Invoke-RestMethod -Uri "$coolifyBase/applications/public" -Method Post -Headers $ch -Body $appBody
    Write-Host "Created application $($app.uuid)" -ForegroundColor Green
} else {
    # Coolify does not expose a PATCH for applications in the documented API;
    # update via UI or delete+recreate if needed.
    Write-Host "Application already exists: $($app.uuid). Skipping update." -ForegroundColor Yellow
}
$appUuid = $app.uuid

# --------------------------------------------------------------------------- #
# 4. Environment variables
# --------------------------------------------------------------------------- #
Write-Section "Setting Coolify environment variables"
$envVars = @(
    @{key = "ADMIN_USERNAME"; value = "admin" }
    @{key = "ADMIN_PASSWORD_HASH"; value = $adminPasswordHash }
    @{key = "SECRET_KEY"; value = $secretKey }
    @{key = "DATABASE_URL"; value = "sqlite:///./data/license_server.db" }
    @{key = "DEFAULT_OFFLINE_GRACE_DAYS"; value = "10" }
    @{key = "DEFAULT_ACTIVATION_LIMIT"; value = "1" }
    @{key = "DEBUG"; value = "false" }
)
$existingEnv = Invoke-RestMethod -Uri "$coolifyBase/applications/$appUuid/envs" -Headers $ch
foreach ($ev in $envVars) {
    $existing = $existingEnv | Where-Object { $_.key -eq $ev.key } | Select-Object -First 1
    if ($existing) {
        Invoke-RestMethod -Uri "$coolifyBase/applications/$appUuid/envs/$($existing.uuid)" -Method Patch -Headers $ch -Body ($ev | ConvertTo-Json) | Out-Null
    } else {
        Invoke-RestMethod -Uri "$coolifyBase/applications/$appUuid/envs" -Method Post -Headers $ch -Body ($ev | ConvertTo-Json) | Out-Null
    }
}
Write-Host "Environment variables set" -ForegroundColor Green

# --------------------------------------------------------------------------- #
# 5. Persistent storage
# --------------------------------------------------------------------------- #
Write-Section "Adding persistent storage"
$existingStorages = Invoke-RestMethod -Uri "$coolifyBase/applications/$appUuid/storages" -Headers $ch
$existingStorage = $existingStorages | Where-Object { $_.mount_path -eq "/app/data" } | Select-Object -First 1
if (-not $existingStorage) {
    $storageBody = @{
        type       = "persistent"
        name       = "license-server-data"
        mount_path = "/app/data"
    } | ConvertTo-Json
    Invoke-RestMethod -Uri "$coolifyBase/applications/$appUuid/storages" -Method Post -Headers $ch -Body $storageBody | Out-Null
    Write-Host "Persistent storage mounted at /app/data" -ForegroundColor Green
} else {
    Write-Host "Persistent storage already exists" -ForegroundColor Green
}

# --------------------------------------------------------------------------- #
# 6. Deploy
# --------------------------------------------------------------------------- #
Write-Section "Triggering deployment"
$deploy = Invoke-RestMethod -Uri "$coolifyBase/deploy?uuid=$appUuid&force=true" -Method Post -Headers $ch
Write-Host "Deployment queued: $($deploy | ConvertTo-Json -Depth 3)" -ForegroundColor Green

# --------------------------------------------------------------------------- #
# 7. Wait for health check
# --------------------------------------------------------------------------- #
Write-Section "Waiting for deployment to be healthy"
$healthUrl = "https://$domain/admin/health"
for ($i = 0; $i -lt 60; $i++) {
    Start-Sleep -Seconds 10
    try {
        $r = Invoke-RestMethod -Uri $healthUrl -TimeoutSec 10
        if ($r.status -eq "ok") {
            Write-Host "`nDeployment is live: $healthUrl" -ForegroundColor Green
            Write-Host "Admin URL: https://$domain/admin" -ForegroundColor Green
            break
        }
    } catch {
        Write-Host "." -NoNewline
    }
}

Write-Section "Deployment summary"
Write-Host "Domain:        https://$domain"
Write-Host "Health:        https://$domain/admin/health"
Write-Host "Admin user:    admin"
Write-Host "App UUID:      $appUuid"
Write-Host "`nSecret key and admin password hash have been configured in Coolify."
Write-Host "Back up the persistent /app/data volume; it contains the DB and Ed25519 keys."

} finally {
    # Overwrite and delete the secrets file so token values are not left on disk.
    Remove-SecretsFile $SecretsPath
    Write-Section "Cleaned up secrets file"
}
