Param(
    [string]$BuildDir = "build",
    [string]$CliPath = ""
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot

if (-not $CliPath) {
    $CliPath = Join-Path $root "$BuildDir\cli\quantum-migrate.exe"
}

if (-not (Test-Path $CliPath)) {
    Write-Error "CLI not found at $CliPath. Build the project first (cmake --build $BuildDir)."
}

$demoRoot = Join-Path $root "experiments\demo_repos"
$resultsRoot = Join-Path $root "experiments\results"

$repos = @(
    "cpp_legacy_service",
    "python_flask_api",
    "node_ts_api",
    "java_maven_app",
    "go_service",
    "rust_service",
    "dotnet_crypto_app",
    "mixed_monorepo",
    "config_secrets_repo",
    "clean_modern_repo",
    "legacy_crypto_lib"
)

Write-Host "Root:        $root"
Write-Host "CLI:         $CliPath"
Write-Host "Demo repos:  $demoRoot"
Write-Host "Results dir: $resultsRoot"
Write-Host ""

foreach ($repo in $repos) {
    $target = Join-Path $demoRoot $repo
    if (-not (Test-Path $target)) {
        Write-Warning "Skipping $repo (missing at $target)"
        continue
    }

    $outDir = Join-Path $resultsRoot $repo
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null

    Write-Host "====================================================="
    Write-Host "Running quantum-migrate on repo: $repo"
    Write-Host "Target:  $target"
    Write-Host "Output:  $outDir"
    Write-Host "====================================================="

    $cmdBase = "`"$CliPath`" `"$target`""

    # Run 1: Text report (audit_report.txt)
    $textReport = Join-Path $outDir "audit_report.txt"
    $textLog    = Join-Path $outDir "run_text_stdout_stderr.txt"
    Write-Host "[Run A] Text report -> $textReport"
    $start = Get-Date
    & $CliPath $target --output $textReport *>&1 | Tee-Object -FilePath $textLog
    $end = Get-Date
    $elapsedMs = [int](($end - $start).TotalMilliseconds)
    Set-Content -Path (Join-Path $outDir "run_text_timing.txt") -Value "start=$start`nend=$end`nelapsed_ms=$elapsedMs"

    # Run 2: SARIF report
    $sarifReport = Join-Path $outDir "quantum_scan.sarif"
    $sarifLog    = Join-Path $outDir "run_sarif_stdout_stderr.txt"
    Write-Host "[Run B] SARIF report -> $sarifReport"
    $start = Get-Date
    & $CliPath $target --format sarif --output $sarifReport *>&1 | Tee-Object -FilePath $sarifLog
    $end = Get-Date
    $elapsedMs = [int](($end - $start).TotalMilliseconds)
    Set-Content -Path (Join-Path $outDir "run_sarif_timing.txt") -Value "start=$start`nend=$end`nelapsed_ms=$elapsedMs"

    # Run 3: Enriched scan with entropy + proximity
    $richReport = Join-Path $outDir "audit_report_rich.txt"
    $richLog    = Join-Path $outDir "run_rich_stdout_stderr.txt"
    Write-Host "[Run C] Rich scan (entropy+proximity) -> $richReport"
    $start = Get-Date
    & $CliPath $target --entropy --proximity --output $richReport *>&1 | Tee-Object -FilePath $richLog
    $end = Get-Date
    $elapsedMs = [int](($end - $start).TotalMilliseconds)
    Set-Content -Path (Join-Path $outDir "run_rich_timing.txt") -Value "start=$start`nend=$end`nelapsed_ms=$elapsedMs"

    # Run 4: AI remediation + patch (requires model to exist)
    $model = Join-Path $root "models\Qwen2.5-Coder-14B-Instruct-F16.gguf"
    if (Test-Path $model) {
        $patchPath = Join-Path $outDir "quantum_fixes.patch"
        $aiLog     = Join-Path $outDir "run_ai_stdout_stderr.txt"
        Write-Host "[Run D] AI remediation + patch -> $patchPath"
        $start = Get-Date
        $prevErrPref = $ErrorActionPreference
        try {
            $ErrorActionPreference = "Continue"
            & $CliPath $target --remediate --model $model --patch $patchPath --backup *>&1 | Tee-Object -FilePath $aiLog
        } finally {
            $ErrorActionPreference = $prevErrPref
        }
        $end = Get-Date
        $elapsedMs = [int](($end - $start).TotalMilliseconds)
        Set-Content -Path (Join-Path $outDir "run_ai_timing.txt") -Value "start=$start`nend=$end`nelapsed_ms=$elapsedMs"
    }

    # Copy ground truth into results for easier analysis
    $gtSrc = Join-Path $target "GROUND_TRUTH.txt"
    if (Test-Path $gtSrc) {
        Copy-Item $gtSrc (Join-Path $outDir "GROUND_TRUTH.txt") -Force
    }
}

Write-Host ""
Write-Host "All repos processed. Check per-repo folders under:"
Write-Host "  $resultsRoot"

