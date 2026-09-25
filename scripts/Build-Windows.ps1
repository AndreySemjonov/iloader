[CmdletBinding()]
param(
    [switch]$BuildExecutable,
    [switch]$Offline,
    [string]$FrontendDependencies
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
function Run([string]$Program, [string[]]$Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" }
}
function Hash([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

$repository = Split-Path -Parent $PSScriptRoot
Push-Location $repository
try {
    foreach ($program in @('git', 'bun', 'cargo', 'rustc')) {
        Get-Command $program -ErrorAction Stop | Out-Null
    }
    if ($env:OS -ne 'Windows_NT') { throw 'Use this script on Windows with the MSVC Rust toolchain.' }
    $commit = (& git rev-parse HEAD).Trim()
    if ($LASTEXITCODE) { throw 'Run this script from a Git checkout.' }
    $dirty = [bool](& git status --porcelain)
    if ($LASTEXITCODE) { throw 'Cannot read source status.' }
    $artifacts = Join-Path $repository 'artifacts/windows'
    New-Item -ItemType Directory -Path $artifacts -Force | Out-Null
    # Clear only this helper's generated files, including results from failed runs.
    # A checks-only run must never publish an older executable as its own output.
    foreach ($name in @('iloader.exe', 'BUILD.json', 'SHA256SUMS.txt')) {
        $previous = Join-Path $artifacts $name
        if (Test-Path -LiteralPath $previous) { Remove-Item -LiteralPath $previous }
    }
    if ($Offline -and -not $FrontendDependencies) {
        throw 'Offline builds require FrontendDependencies pointing to prepared node_modules beside a matching bun.lock.'
    }
    if ($FrontendDependencies) {
        $prepared = (Resolve-Path -LiteralPath $FrontendDependencies).Path
        if ((Split-Path -Leaf $prepared) -ne 'node_modules') { throw 'FrontendDependencies must name node_modules.' }
        $preparedLock = Join-Path (Split-Path -Parent $prepared) 'bun.lock'
        if ((Hash $preparedLock) -ne (Hash 'bun.lock')) { throw 'Prepared frontend dependencies use a different bun.lock.' }
        $modules = Join-Path $repository 'node_modules'
        if ($prepared -ine $modules) {
            if (Test-Path -LiteralPath $modules) { throw 'node_modules already exists; use it explicitly or choose a fresh checkout.' }
            New-Item -ItemType Junction -Path $modules -Target $prepared | Out-Null
        }
    } else {
        Run 'bun' @('install', '--frozen-lockfile', '--ignore-scripts')
    }
    Run 'bun' @('run', 'build')

    $cargoOptions = @('--locked', '--manifest-path', 'src-tauri/Cargo.toml')
    if ($Offline) { $cargoOptions += '--offline' }
    foreach ($package in @('iloader', 'isideload')) {
        Run 'cargo' (@('test') + $cargoOptions + @('--lib', '-p', $package))
    }

    $metadata = & cargo metadata @cargoOptions --no-deps --format-version 1
    if ($LASTEXITCODE) { throw 'Cannot locate Cargo output directory.' }
    $target = ($metadata | ConvertFrom-Json).target_directory
    $executable = $null
    $executableHash = $null
    if ($BuildExecutable) {
        $arguments = @('run', 'tauri', 'build', '--no-bundle', '--config', 'src-tauri/ci.conf.json', '--', '--locked')
        if ($Offline) { $arguments += '--offline' }
        Run 'bun' $arguments
        $executable = Join-Path $artifacts 'iloader.exe'
        Copy-Item -LiteralPath (Join-Path $target 'release/iloader.exe') -Destination $executable
        $executableHash = Hash $executable
    }
    $result = [ordered]@{
        completedUtc = [DateTime]::UtcNow.ToString('o')
        sourceCommit = $commit
        sourceDirty = $dirty
        cargoLockSha256 = Hash 'src-tauri/Cargo.lock'
        bunLockSha256 = Hash 'bun.lock'
        rustVersion = (& rustc --version) -join ' '
        bunVersion = (& bun --version) -join ' '
        frontend = 'passed'
        rustSuites = 'iloader and isideload unit tests passed'
        executable = $(if ($BuildExecutable) { 'iloader.exe' } else { $null })
        executableSha256 = $executableHash
    }
    $report = Join-Path $artifacts 'BUILD.json'
    $result | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $report -Encoding utf8
    $checksums = @((Hash $report) + '  BUILD.json')
    if ($BuildExecutable) { $checksums += $executableHash + '  iloader.exe' }
    $checksums | Set-Content -LiteralPath (Join-Path $artifacts 'SHA256SUMS.txt') -Encoding ascii
    Write-Output "Build checks passed. Report: $report"
    if ($BuildExecutable) { Write-Output "Executable: $executable (SHA-256: $executableHash)" }
} finally {
    Pop-Location
}
