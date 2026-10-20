param(
    [ValidateSet('status', 'prepare', 'test', 'report', 'setup')]
    [string]$Command = 'status',
    [ValidateSet('host-only', 'offline')]
    [string]$Mode = 'host-only',
    [ValidateSet('syntax', 'synthetic', 'pdf-static')]
    [string]$Kind = 'synthetic',
    [switch]$Refresh,
    [switch]$Help
)
$ErrorActionPreference = 'Stop'
if ($Help) {
    Write-Output '.\lab.ps1 status|prepare|test|report|setup [-Mode offline] [-Kind syntax|synthetic|pdf-static] [-Refresh]'
    Write-Output 'test is operator-only. Offline jobs are queued before disconnection. No command changes VM networking.'
    exit 0
}
$LabPython = Join-Path $PSScriptRoot '.venv-windows-dev\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $LabPython -PathType Leaf)) {
    throw 'Dedicated Python is missing. Follow INSTALL.md; no packages are installed automatically.'
}
$LabArguments = @((Join-Path $PSScriptRoot 'scripts\lab\labctl.py'), 'workflow', $Command, '--mode', $Mode, '--kind', $Kind)
if ($Refresh) { $LabArguments += '--refresh' }
Push-Location $PSScriptRoot
try {
    & $LabPython @LabArguments
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
