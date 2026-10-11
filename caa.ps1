<#
  code-audit-agent in Docker for Windows PowerShell (no WSL needed, only Docker Desktop).

  Examples:
    .\caa.ps1 scan https://github.com/owner/repo
    .\caa.ps1 scan owner/repo --ref develop --llm
    .\caa.ps1 scan C:\projects\my-app
    .\caa.ps1 scan C:\projects\my-app --trust-target --run-app --sandbox-network egress --install-deps
    .\caa.ps1 rebuild          # rebuild the image after `git pull`

  Reports appear in .\caa-reports\<name>-<date>\report.html (open it in a browser).
  A .env file next to this script (model API keys, CAA_GIT_TOKEN for private repos) is passed in.
#>
# not "Stop": in Windows PowerShell 5.1 any stderr line of a native command (docker prints progress
# and "No such image" there) would become a terminating error. Exit codes are checked explicitly.
$ErrorActionPreference = "Continue"
$Image = "code-audit-agent"
$Root = $PSScriptRoot
$Reports = Join-Path (Get-Location) "caa-reports"

if ($args.Count -gt 0 -and $args[0] -eq "rebuild") {
    docker build -t $Image $Root
    exit $LASTEXITCODE
}
$found = docker images -q $Image
if ($LASTEXITCODE -ne 0) { Write-Host "[caa] Docker is not running - start Docker Desktop and try again"; exit 1 }
if (-not $found) {
    Write-Host "[caa] building the Docker image (first run, takes a few minutes)..."
    docker build -t $Image $Root
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
New-Item -ItemType Directory -Force -Path $Reports | Out-Null

$dockerArgs = @("run", "--rm", "-t", "-v", "${Reports}:/out")
$envFile = Join-Path $Root ".env"
if (Test-Path $envFile) { $dockerArgs += @("--env-file", $envFile) }

$caaArgs = @()
$mounted = $false
foreach ($a in $args) {
    # a local folder argument is mounted read-only at /target
    if (-not $mounted -and $a -notmatch '^(https?://|-)' -and (Test-Path -LiteralPath $a -PathType Container)) {
        $full = (Resolve-Path -LiteralPath $a).Path
        $dockerArgs += @("-v", "${full}:/target:ro")
        $caaArgs += "/target"
        $mounted = $true
    } else {
        $caaArgs += $a
    }
}
# the sandbox inside the container uses user namespaces (unshare), blocked by Docker's default seccomp profile
if ($caaArgs -contains "--trust-target") { $dockerArgs += @("--security-opt", "seccomp=unconfined", "--security-opt", "apparmor=unconfined") }

& docker @dockerArgs $Image @caaArgs
exit $LASTEXITCODE
