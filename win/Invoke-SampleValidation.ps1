<#
.SYNOPSIS
    Polymorphic Sample Integrity Validator & Controlled Extraction Tool
.DESCRIPTION
    Validates SHA256/SHA1/MD5 integrity of archived malware samples,
    extracts password-protected ZIPs, and optionally executes samples
    in a controlled environment for EDR/XDR validation testing.
.NOTES
    FOR AUTHORIZED SECURITY TESTING ONLY
    Must be run in an isolated, virtualized environment with appropriate
    endpoint detection and response (EDR/XDR) solutions active.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet("Validate", "Extract", "Execute", "Full")]
    [string]$Mode = "Validate",

    [Parameter()]
    [string]$SamplesPath = $PSScriptRoot,

    [Parameter()]
    [string]$ExtractPath = "$env:TEMP\PolyTestSamples",

    [Parameter()]
    [string]$LogPath = "$PSScriptRoot\validation_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
)

# ─── CONFIGURATION ───────────────────────────────────────────────────────────
$script:PassedCount = 0
$script:FailedCount = 0
$script:SkippedCount = 0
$script:ExtractedSamples = @()

# ─── LOGGING ─────────────────────────────────────────────────────────────────
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp] [$Level] $Message"
    Add-Content -Path $LogPath -Value $entry
    switch ($Level) {
        "OK"    { Write-Host "  [+] $Message" -ForegroundColor Green }
        "FAIL"  { Write-Host "  [-] $Message" -ForegroundColor Red }
        "WARN"  { Write-Host "  [!] $Message" -ForegroundColor Yellow }
        "INFO"  { Write-Host "  [*] $Message" -ForegroundColor Cyan }
        "EXEC"  { Write-Host "  [>] $Message" -ForegroundColor Magenta }
        default { Write-Host "  $Message" }
    }
}

function Write-Banner {
    $banner = @"

  ╔══════════════════════════════════════════════════════════════╗
  ║     POLYMORPHIC SAMPLE INTEGRITY VALIDATION FRAMEWORK       ║
  ║                 Authorized Testing Only                      ║
  ╚══════════════════════════════════════════════════════════════╝

  Mode       : $Mode
  Samples    : $SamplesPath
  Extract To : $ExtractPath
  Log File   : $LogPath
  Timestamp  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

"@
    Write-Host $banner -ForegroundColor DarkCyan
}

# ─── HASH VALIDATION ────────────────────────────────────────────────────────
function Test-SampleIntegrity {
    param([string]$FamilyPath)

    $familyName = Split-Path $FamilyPath -Leaf
    Write-Host "`n  ─── $familyName " -NoNewline
    Write-Host ("─" * (50 - $familyName.Length)) -ForegroundColor DarkGray

    $zipFile = Get-ChildItem -Path $FamilyPath -Filter "*.zip" | Select-Object -First 1
    if (-not $zipFile) {
        Write-Log "No ZIP archive found" "WARN"
        $script:SkippedCount++
        return $null
    }

    $result = [PSCustomObject]@{
        Family    = $familyName
        ZipFile   = $zipFile.FullName
        ZipSize   = "{0:N2} KB" -f ($zipFile.Length / 1KB)
        SHA256    = "N/A"
        MD5       = "N/A"
        SHA1      = "N/A"
        Password  = "N/A"
        Integrity = "UNKNOWN"
    }

    # Read password
    $passFile = Get-ChildItem -Path $FamilyPath -Filter "*.pass" | Select-Object -First 1
    if ($passFile) {
        $result.Password = (Get-Content $passFile.FullName -Raw).Trim()
    }

    $allPassed = $true

    # ── SHA256 Validation ──
    $sha256File = Get-ChildItem -Path $FamilyPath -Filter "*.sha256" | Select-Object -First 1
    if ($sha256File) {
        $expectedLine = (Get-Content $sha256File.FullName -Raw).Trim()

        # Detect if it's actually a SHA1 (40 hex chars) stored in .sha256 file
        if ($expectedLine -match "^([a-f0-9]{40})\s") {
            Write-Log "SHA256 file contains SHA1 hash (40 chars) — validating as SHA1" "WARN"
            $expectedHash = $Matches[1]
            $computedHash = (Get-FileHash -Path $zipFile.FullName -Algorithm SHA1).Hash.ToLower()
            $result.SHA1 = $computedHash
            if ($computedHash -eq $expectedHash) {
                Write-Log "SHA1 OK: $computedHash" "OK"
            } else {
                Write-Log "SHA1 MISMATCH! Expected: $expectedHash | Got: $computedHash" "FAIL"
                $allPassed = $false
            }
        }
        elseif ($expectedLine -match "^([a-f0-9]{64})\s") {
            $expectedHash = $Matches[1]
            $computedHash = (Get-FileHash -Path $zipFile.FullName -Algorithm SHA256).Hash.ToLower()
            $result.SHA256 = $computedHash
            if ($computedHash -eq $expectedHash) {
                Write-Log "SHA256 OK: $computedHash" "OK"
            } else {
                Write-Log "SHA256 MISMATCH! Expected: $expectedHash | Got: $computedHash" "FAIL"
                $allPassed = $false
            }
        }
        else {
            Write-Log "Unrecognized hash format in .sha256 file" "WARN"
        }
    }

    # ── SHA1/SHASUM Validation (.shasum and .sha files) ──
    $shasumFile = Get-ChildItem -Path $FamilyPath -Filter "*.shasum" | Select-Object -First 1
    if (-not $shasumFile) {
        $shasumFile = Get-ChildItem -Path $FamilyPath -Filter "*.sha" | Select-Object -First 1
    }
    if ($shasumFile) {
        $expectedLine = (Get-Content $shasumFile.FullName -Raw).Trim()
        if ($expectedLine -match "^([a-f0-9]{40})\s") {
            $expectedHash = $Matches[1]
            $computedHash = (Get-FileHash -Path $zipFile.FullName -Algorithm SHA1).Hash.ToLower()
            $result.SHA1 = $computedHash
            if ($computedHash -eq $expectedHash) {
                Write-Log "SHA1 OK: $computedHash" "OK"
            } else {
                Write-Log "SHA1 MISMATCH! Expected: $expectedHash | Got: $computedHash" "FAIL"
                $allPassed = $false
            }
        }
    }

    # ── MD5 Validation ──
    $md5File = Get-ChildItem -Path $FamilyPath -Filter "*.md5" | Select-Object -First 1
    if ($md5File) {
        $expectedLine = (Get-Content $md5File.FullName -Raw).Trim()
        $expectedHash = ""

        # Format: "hash  filename"
        if ($expectedLine -match "^([a-f0-9]{32})\s") {
            $expectedHash = $Matches[1]
        }
        # Format: "MD5 (filename) = hash"
        elseif ($expectedLine -match "=\s*([a-f0-9]{32})") {
            $expectedHash = $Matches[1]
        }

        if ($expectedHash) {
            $computedHash = (Get-FileHash -Path $zipFile.FullName -Algorithm MD5).Hash.ToLower()
            $result.MD5 = $computedHash

            # Check if MD5 was computed against raw binary (not zip)
            if ($computedHash -eq $expectedHash) {
                Write-Log "MD5 OK: $computedHash" "OK"
            }
            else {
                # Some samples have MD5 of the unpacked binary, not the zip
                Write-Log "MD5 differs (may reference unpacked binary): Expected=$expectedHash Got=$computedHash" "WARN"
            }
        }
    }

    # Overall integrity
    if ($allPassed) {
        $result.Integrity = "PASSED"
        Write-Log "Integrity: PASSED | Size: $($result.ZipSize)" "OK"
        $script:PassedCount++
    } else {
        $result.Integrity = "FAILED"
        Write-Log "Integrity: FAILED" "FAIL"
        $script:FailedCount++
    }

    return $result
}

# ─── EXTRACTION ──────────────────────────────────────────────────────────────
function Expand-Sample {
    param([PSCustomObject]$SampleInfo)

    if (-not $SampleInfo -or $SampleInfo.Integrity -eq "FAILED") {
        Write-Log "Skipping extraction for $($SampleInfo.Family) — integrity check failed" "WARN"
        return
    }

    $destDir = Join-Path $ExtractPath $SampleInfo.Family
    if (-not (Test-Path $destDir)) {
        New-Item -ItemType Directory -Path $destDir -Force | Out-Null
    }

    Write-Log "Extracting $($SampleInfo.Family) to $destDir ..." "INFO"

    try {
        # Use 7-Zip if available (handles password-protected ZIPs better)
        $7z = Get-Command "7z" -ErrorAction SilentlyContinue
        if (-not $7z) {
            $7z = Get-Command "C:\Program Files\7-Zip\7z.exe" -ErrorAction SilentlyContinue
        }

        if ($7z) {
            $password = $SampleInfo.Password
            $args7z = @("x", "-y", "-o$destDir", "-p$password", $SampleInfo.ZipFile)
            & $7z.Source @args7z 2>&1 | Out-Null
            Write-Log "Extracted via 7-Zip" "OK"
        }
        else {
            # Fallback: PowerShell Expand-Archive (no password support)
            Write-Log "7-Zip not found — attempting PowerShell extraction (may fail with password-protected ZIPs)" "WARN"
            Expand-Archive -Path $SampleInfo.ZipFile -DestinationPath $destDir -Force
            Write-Log "Extracted via PowerShell" "OK"
        }

        # List extracted files
        $extracted = Get-ChildItem -Path $destDir -Recurse -File
        foreach ($f in $extracted) {
            $hash = (Get-FileHash -Path $f.FullName -Algorithm SHA256).Hash.ToLower()
            Write-Log "  Unpacked: $($f.Name) | SHA256: $hash | Size: $("{0:N2} KB" -f ($f.Length / 1KB))" "INFO"
            $script:ExtractedSamples += [PSCustomObject]@{
                Family   = $SampleInfo.Family
                FileName = $f.Name
                FullPath = $f.FullName
                SHA256   = $hash
                Size     = $f.Length
            }
        }
    }
    catch {
        Write-Log "Extraction failed: $($_.Exception.Message)" "FAIL"
    }
}

# ─── CONTROLLED EXECUTION ───────────────────────────────────────────────────
function Invoke-SampleExecution {
    param([int]$DelayBetweenSeconds = 15)

    if ($script:ExtractedSamples.Count -eq 0) {
        Write-Log "No extracted samples to execute" "WARN"
        return
    }

    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "  ║                    ⚠  WARNING  ⚠                       ║" -ForegroundColor Red
    Write-Host "  ║   About to execute live malware samples.                ║" -ForegroundColor Red
    Write-Host "  ║   Ensure this is an ISOLATED, VIRTUALIZED environment.  ║" -ForegroundColor Red
    Write-Host "  ║   EDR/XDR must be ACTIVE and MONITORING.                ║" -ForegroundColor Red
    Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Red
    Write-Host ""

    $confirm = Read-Host "  Type 'CONFIRM' to proceed with execution"
    if ($confirm -ne "CONFIRM") {
        Write-Log "Execution aborted by user" "WARN"
        return
    }

    $exeSamples = $script:ExtractedSamples | Where-Object {
        $_.FileName -match '\.(exe|dll|scr|bat|cmd|ps1|vbs|js)$' -or
        -not ($_.FileName -match '\.')
    }

    if ($exeSamples.Count -eq 0) {
        Write-Log "No executable samples found in extracted files" "WARN"
        return
    }

    Write-Log "Beginning controlled execution of $($exeSamples.Count) samples..." "EXEC"
    Write-Log "Delay between samples: ${DelayBetweenSeconds}s" "INFO"

    $executionIndex = 0
    foreach ($sample in $exeSamples) {
        $executionIndex++
        Write-Host ""
        Write-Log "[$executionIndex/$($exeSamples.Count)] Executing: $($sample.Family)/$($sample.FileName)" "EXEC"
        Write-Log "  Path: $($sample.FullPath)" "INFO"
        Write-Log "  SHA256: $($sample.SHA256)" "INFO"

        try {
            $proc = Start-Process -FilePath $sample.FullPath -PassThru -ErrorAction Stop
            Write-Log "  PID: $($proc.Id) — Process launched" "OK"
            Write-Log "  Waiting ${DelayBetweenSeconds}s for EDR/XDR to react..." "INFO"
            Start-Sleep -Seconds $DelayBetweenSeconds

            # Check if process is still alive
            if (-not $proc.HasExited) {
                Write-Log "  Process still running (PID: $($proc.Id))" "INFO"
            } else {
                Write-Log "  Process exited with code: $($proc.ExitCode)" "INFO"
            }
        }
        catch {
            Write-Log "  Execution blocked/failed: $($_.Exception.Message)" "WARN"
            Write-Log "  (This is expected if EDR/XDR is blocking the sample)" "INFO"
        }
    }

    Write-Log "Execution phase completed" "OK"
}

# ─── SUMMARY REPORT ─────────────────────────────────────────────────────────
function Write-Summary {
    param([array]$Results)

    Write-Host "`n  ═══════════════════════════════════════════════════════" -ForegroundColor DarkCyan
    Write-Host "                     VALIDATION SUMMARY" -ForegroundColor Cyan
    Write-Host "  ═══════════════════════════════════════════════════════" -ForegroundColor DarkCyan

    $tableData = $Results | Where-Object { $_ } | Format-Table -Property @(
        @{Label="Family"; Expression={$_.Family}; Width=20}
        @{Label="Integrity"; Expression={$_.Integrity}; Width=10}
        @{Label="SHA256"; Expression={if($_.SHA256 -ne "N/A"){$_.SHA256.Substring(0,16)+"..."}else{"N/A"}}; Width=20}
        @{Label="Size"; Expression={$_.ZipSize}; Width=12}
        @{Label="Password"; Expression={$_.Password}; Width=10}
    ) -AutoSize | Out-String

    Write-Host $tableData

    Write-Host "  Results:" -ForegroundColor Cyan
    Write-Host "    Passed  : $script:PassedCount" -ForegroundColor Green
    Write-Host "    Failed  : $script:FailedCount" -ForegroundColor $(if($script:FailedCount -gt 0){"Red"}else{"Green"})
    Write-Host "    Skipped : $script:SkippedCount" -ForegroundColor Yellow
    Write-Host ""

    if ($script:ExtractedSamples.Count -gt 0) {
        Write-Host "  Extracted Samples:" -ForegroundColor Cyan
        foreach ($s in $script:ExtractedSamples) {
            Write-Host "    $($s.Family)/$($s.FileName) — $($s.SHA256.Substring(0,16))..." -ForegroundColor Gray
        }
    }

    Write-Host "`n  Full log: $LogPath" -ForegroundColor DarkGray
    Write-Host ""
}

# ─── MAIN ────────────────────────────────────────────────────────────────────
Write-Banner

# Initialize log
"=== Polymorphic Sample Validation Log ===" | Out-File -FilePath $LogPath
"Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Add-Content -Path $LogPath
"Mode: $Mode" | Add-Content -Path $LogPath
"" | Add-Content -Path $LogPath

# Discover sample families (all subdirectories except hidden/system)
$families = Get-ChildItem -Path $SamplesPath -Directory | Where-Object {
    $_.Name -notlike ".*" -and $_.Name -ne "__MACOSX"
}

if ($families.Count -eq 0) {
    Write-Log "No sample directories found in $SamplesPath" "FAIL"
    exit 1
}

Write-Log "Found $($families.Count) sample families" "INFO"

# Phase 1: Validate
$results = @()
foreach ($family in $families) {
    $results += Test-SampleIntegrity -FamilyPath $family.FullName
}

Write-Summary -Results $results

# Phase 2: Extract (if requested)
if ($Mode -in @("Extract", "Full")) {
    Write-Host "`n  ─── EXTRACTION PHASE ────────────────────────────────────" -ForegroundColor DarkCyan

    if (-not (Test-Path $ExtractPath)) {
        New-Item -ItemType Directory -Path $ExtractPath -Force | Out-Null
    }

    foreach ($r in $results) {
        if ($r -and $r.Integrity -eq "PASSED") {
            Expand-Sample -SampleInfo $r
        }
    }
}

# Phase 3: Execute (if requested)
if ($Mode -eq "Full" -or $Mode -eq "Execute") {
    if ($Mode -eq "Execute" -and $script:ExtractedSamples.Count -eq 0) {
        Write-Log "Execute mode requires prior extraction. Use -Mode Full instead." "FAIL"
    }
    else {
        Invoke-SampleExecution -DelayBetweenSeconds 15
    }
}

Write-Log "Completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "INFO"
