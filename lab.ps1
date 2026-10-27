param(
    [ValidateSet('status', 'prepare', 'test', 'report', 'setup', 'verify', 'doctor')]
    [string]$Command = 'status',
    [ValidateSet('host-only', 'offline', 'syntax', 'synthetic')]
    [string]$Mode = 'host-only',
    [ValidateSet('syntax', 'synthetic', 'pdf-static', 'pdf-static-cve')]
    [string]$Kind = 'synthetic',
    [switch]$Refresh,
    [switch]$Gateway,
    [switch]$Transfer,
    [switch]$Operator,
    [switch]$Help
)
$ErrorActionPreference = 'Stop'
if ($Help) {
    Write-Output '.\lab.ps1 status|prepare|test|report|setup|verify|doctor [-Mode syntax|synthetic|offline] [-Kind syntax|synthetic|pdf-static|pdf-static-cve] [-Refresh] [-Gateway] [-Transfer] [-Operator]'
    Write-Output 'doctor reads bounded diagnostic metadata through the audit key and never starts or repairs services.'
    Write-Output 'Connected test uses the verified restricted gateway. setup -Gateway prepares its installer locally. Offline/admin workflows require the operator.'
    Write-Output 'setup -Gateway -Transfer copies the installer only, after operator confirmation in a separate interactive terminal.'
    Write-Output 'setup -Mode offline -Transfer copies the offline console installer; prepare -Mode offline -Kind pdf-static creates a local unapproved plan without reading PDFs.'
    exit 0
}
$LabPython = Join-Path $PSScriptRoot '.venv-windows-dev\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $LabPython -PathType Leaf)) {
    throw 'Dedicated Python is missing. Follow INSTALL.md; no packages are installed automatically.'
}
$LabArguments = @((Join-Path $PSScriptRoot 'scripts\lab\labctl.py'), 'workflow', $Command, '--mode', $Mode, '--kind', $Kind)
if ($Refresh) { $LabArguments += '--refresh' }
if ($Gateway) { $LabArguments += '--gateway' }
if ($Operator) { $LabArguments += '--operator' }
if ($Transfer) {
    if ($Command -ne 'setup' -or $Operator -or $Refresh -or -not (($Gateway -and $Mode -eq 'host-only') -or (-not $Gateway -and $Mode -eq 'offline'))) {
        throw 'Transfer requires setup -Gateway -Transfer or setup -Mode offline -Transfer.'
    }
    $LabArguments = @((Join-Path $PSScriptRoot 'scripts\lab\gateway_transfer.py'))
    if ($Mode -eq 'offline') { $LabArguments += '--offline' }
}
Push-Location $PSScriptRoot
try {
    & $LabPython @LabArguments
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
