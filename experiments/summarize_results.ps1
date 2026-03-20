Param(
    [string]$ResultsDir = ""
)

$ErrorActionPreference = "Stop"

if (-not $ResultsDir) {
    $ResultsDir = Join-Path (Split-Path -Parent $PSScriptRoot) "experiments\results"
}

if (-not (Test-Path $ResultsDir)) {
    Write-Error "Results directory not found: $ResultsDir"
}

$summaryTxt = Join-Path $ResultsDir "EXPERIMENT_SUMMARY.txt"
$summaryCsv = Join-Path $ResultsDir "EXPERIMENT_SUMMARY.csv"

"Repo,FindingsText,FindingsRich" | Set-Content -Path $summaryCsv
"" | Set-Content -Path $summaryTxt

Get-ChildItem -Path $ResultsDir -Directory | ForEach-Object {
    $repo = $_.Name
    $repoDir = $_.FullName

    $audit = Join-Path $repoDir "audit_report.txt"
    $auditRich = Join-Path $repoDir "audit_report_rich.txt"

    $countText = 0
    $countRich = 0

    if (Test-Path $audit) {
        $countText = (Select-String -Path $audit -Pattern "^\[FINDINGS\]" -Context 0,1 -ErrorAction SilentlyContinue |
            ForEach-Object {
                if ($_ -match "([0-9]+) vulnerabilities detected") { [int]$matches[1] }
            }) | Select-Object -First 1
        if (-not $countText) { $countText = 0 }
    }

    if (Test-Path $auditRich) {
        $countRich = (Select-String -Path $auditRich -Pattern "^\[FINDINGS\]" -Context 0,1 -ErrorAction SilentlyContinue |
            ForEach-Object {
                if ($_ -match "([0-9]+) vulnerabilities detected") { [int]$matches[1] }
            }) | Select-Object -First 1
        if (-not $countRich) { $countRich = 0 }
    }

    $lineTxt = "Repo: $repo`n  Findings (text): $countText`n  Findings (rich): $countRich`n"
    Add-Content -Path $summaryTxt -Value $lineTxt

    "$repo,$countText,$countRich" | Add-Content -Path $summaryCsv
}

Write-Host "Summary written:"
Write-Host "  $summaryTxt"
Write-Host "  $summaryCsv"

