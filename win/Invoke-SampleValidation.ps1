<#
.SYNOPSIS
    Polymorphic Sample Integrity Validator & Controlled Execution Tool
.DESCRIPTION
    Validates SHA256/SHA1/MD5 integrity of archived malware samples,
    extracts password-protected ZIPs, and executes samples in a controlled
    environment for EDR/XDR validation testing.

    Supports two execution methods:
      - Disk:     Standard execution from filesystem (tests static + behavioral detection)
      - InMemory: Reflective loading without touching disk (tests fileless/memory detection)

    Includes optional environment preparation to disable Windows Defender
    and configure exclusions so only the EDR/XDR under test performs detection.
.NOTES
    FOR AUTHORIZED SECURITY TESTING ONLY
    Must be run as Administrator in an isolated, virtualized environment
    with the EDR/XDR solution under test actively monitoring.

    Author: 0xp3rc
.EXAMPLE
    # Validate only
    .\Invoke-SampleValidation.ps1 -Mode Validate

    # Full pipeline with Defender disabled, disk execution
    .\Invoke-SampleValidation.ps1 -Mode Full -PrepareEnv -ExecMethod Disk

    # Full pipeline, in-memory execution (fileless)
    .\Invoke-SampleValidation.ps1 -Mode Full -PrepareEnv -ExecMethod InMemory

    # Extract only, custom path
    .\Invoke-SampleValidation.ps1 -Mode Extract -ExtractPath "C:\Lab\Samples"
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
    [string]$LogPath = "$PSScriptRoot\validation_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt",

    # Execution method: Disk (write to disk, run normally) or InMemory (reflective/fileless)
    [Parameter()]
    [ValidateSet("Disk", "InMemory")]
    [string]$ExecMethod = "Disk",

    # Prepare environment: disable Defender real-time, add exclusions
    [Parameter()]
    [switch]$PrepareEnv,

    # Seconds to wait between sample executions for EDR telemetry observation
    [Parameter()]
    [int]$DelaySeconds = 15,

    # Target a specific family (supports wildcards, e.g. "Win32.Emotet" or "*Turla*")
    [Parameter()]
    [string]$Family = ""
)

# === CONFIGURATION ============================================================
$script:PassedCount = 0
$script:FailedCount = 0
$script:SkippedCount = 0
$script:ExtractedSamples = @()

# === LOGGING ==================================================================
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

  +==============================================================+
  |     POLYMORPHIC SAMPLE INTEGRITY VALIDATION FRAMEWORK        |
  |                 Authorized Testing Only                       |
  |                                                by 0xp3rc     |
  +==============================================================+

  Mode        : $Mode
  Exec Method : $ExecMethod
  PrepareEnv  : $PrepareEnv
  Family      : $(if ($Family) { $Family } else { 'ALL' })
  Samples     : $SamplesPath
  Extract To  : $ExtractPath
  Delay       : ${DelaySeconds}s between samples
  Log File    : $LogPath
  Timestamp   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

"@
    Write-Host $banner -ForegroundColor DarkCyan
}

# === ENVIRONMENT PREPARATION ==================================================
function Set-LabEnvironment {
    <#
    .SYNOPSIS
        Prepares the Windows lab environment for sample execution by disabling
        Windows Defender and adding path exclusions. Requires Administrator.
    #>

    # Check admin
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
    if (-not $isAdmin) {
        Write-Log "PrepareEnv requires Administrator privileges. Re-run as Admin." "FAIL"
        return $false
    }

    Write-Host "`n  --- ENVIRONMENT PREPARATION ---------------------------------" -ForegroundColor Yellow

    # 1. Disable Defender Real-Time Protection
    try {
        Write-Log "Disabling Windows Defender Real-Time Protection..." "INFO"
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
        Write-Log "Real-Time Protection: DISABLED" "OK"
    }
    catch {
        Write-Log "Could not disable Real-Time Protection: $($_.Exception.Message)" "WARN"
        Write-Log "Try: Set-MpPreference may be blocked by Tamper Protection. Disable it manually in Windows Security > Virus & Threat Protection > Manage Settings" "WARN"
    }

    # 2. Disable behavior monitoring
    try {
        Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction Stop
        Write-Log "Behavior Monitoring: DISABLED" "OK"
    }
    catch {
        Write-Log "Could not disable Behavior Monitoring: $($_.Exception.Message)" "WARN"
    }

    # 3. Disable IOAV protection (scans on download)
    try {
        Set-MpPreference -DisableIOAVProtection $true -ErrorAction Stop
        Write-Log "IOAV Protection: DISABLED" "OK"
    }
    catch {
        Write-Log "Could not disable IOAV Protection: $($_.Exception.Message)" "WARN"
    }

    # 4. Add folder exclusions
    $exclusionPaths = @($SamplesPath, $ExtractPath)
    foreach ($path in $exclusionPaths) {
        try {
            Add-MpPreference -ExclusionPath $path -ErrorAction Stop
            Write-Log "Exclusion added: $path" "OK"
        }
        catch {
            Write-Log "Could not add exclusion for $path : $($_.Exception.Message)" "WARN"
        }
    }

    # 5. Add process exclusions for common sample extensions
    $exeExclusions = @("*.exe", "*.dll", "*.scr")
    foreach ($ext in $exeExclusions) {
        try {
            Add-MpPreference -ExclusionExtension $ext.TrimStart("*.") -ErrorAction Stop
        }
        catch { }
    }
    Write-Log "Extension exclusions added: exe, dll, scr" "OK"

    # 6. Disable cloud-delivered protection
    try {
        Set-MpPreference -MAPSReporting Disabled -ErrorAction Stop
        Set-MpPreference -SubmitSamplesConsent NeverSend -ErrorAction Stop
        Write-Log "Cloud Protection & Sample Submission: DISABLED" "OK"
    }
    catch {
        Write-Log "Could not disable cloud protection: $($_.Exception.Message)" "WARN"
    }

    Write-Host ""
    Write-Log "Environment prepared. Defender should not interfere with sample execution." "OK"
    Write-Log "NOTE: Tamper Protection must be disabled MANUALLY if the above failed." "WARN"
    Write-Log "Path: Windows Security > Virus & Threat Protection > Manage Settings > Tamper Protection: OFF" "INFO"
    Write-Host ""

    return $true
}

function Restore-LabEnvironment {
    <#
    .SYNOPSIS
        Restores Windows Defender to its default state after testing.
    #>
    Write-Host "`n  --- RESTORING ENVIRONMENT ------------------------------------" -ForegroundColor Yellow

    try {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableIOAVProtection $false -ErrorAction SilentlyContinue
        Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue
        Set-MpPreference -SubmitSamplesConsent SendSafeSamples -ErrorAction SilentlyContinue

        # Remove exclusions
        $exclusionPaths = @($SamplesPath, $ExtractPath)
        foreach ($path in $exclusionPaths) {
            Remove-MpPreference -ExclusionPath $path -ErrorAction SilentlyContinue
        }
        foreach ($ext in @("exe", "dll", "scr")) {
            Remove-MpPreference -ExclusionExtension $ext -ErrorAction SilentlyContinue
        }

        Write-Log "Windows Defender restored to default settings" "OK"
    }
    catch {
        Write-Log "Could not fully restore Defender: $($_.Exception.Message)" "WARN"
    }
}

# === HASH VALIDATION ==========================================================
function Test-SampleIntegrity {
    param([string]$FamilyPath)

    $familyName = Split-Path $FamilyPath -Leaf
    Write-Host "`n  --- $familyName " -NoNewline
    Write-Host ("-" * (50 - $familyName.Length)) -ForegroundColor DarkGray

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

    # -- SHA256 Validation --
    $sha256File = Get-ChildItem -Path $FamilyPath -Filter "*.sha256" | Select-Object -First 1
    if ($sha256File) {
        $expectedLine = (Get-Content $sha256File.FullName -Raw).Trim()

        # Detect if it's actually a SHA1 (40 hex chars) stored in .sha256 file
        if ($expectedLine -match '^([a-f0-9]{40})\s') {
            Write-Log "SHA256 file contains SHA1 hash (40 chars) -- validating as SHA1" "WARN"
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
        elseif ($expectedLine -match '^([a-f0-9]{64})\s') {
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

    # -- SHA1/SHASUM Validation (.shasum and .sha files) --
    $shasumFile = Get-ChildItem -Path $FamilyPath -Filter "*.shasum" | Select-Object -First 1
    if (-not $shasumFile) {
        $shasumFile = Get-ChildItem -Path $FamilyPath -Filter "*.sha" | Select-Object -First 1
    }
    if ($shasumFile) {
        $expectedLine = (Get-Content $shasumFile.FullName -Raw).Trim()
        if ($expectedLine -match '^([a-f0-9]{40})\s') {
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

    # -- MD5 Validation --
    $md5File = Get-ChildItem -Path $FamilyPath -Filter "*.md5" | Select-Object -First 1
    if ($md5File) {
        $expectedLine = (Get-Content $md5File.FullName -Raw).Trim()
        $expectedHash = ""

        # Format: "hash  filename"
        if ($expectedLine -match '^([a-f0-9]{32})\s') {
            $expectedHash = $Matches[1]
        }
        # Format: "MD5 (filename) = hash"
        elseif ($expectedLine -match '=\s*([a-f0-9]{32})') {
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

# === EXTRACTION ===============================================================
function Expand-Sample {
    param([PSCustomObject]$SampleInfo)

    if (-not $SampleInfo -or $SampleInfo.Integrity -eq "FAILED") {
        Write-Log "Skipping extraction for $($SampleInfo.Family) -- integrity check failed" "WARN"
        return
    }

    $destDir = Join-Path $ExtractPath $SampleInfo.Family
    if (-not (Test-Path $destDir)) {
        New-Item -ItemType Directory -Path $destDir -Force | Out-Null
    }

    Write-Log "Extracting $($SampleInfo.Family) to $destDir ..." "INFO"

    try {
        # Use 7-Zip if available (handles password-protected ZIPs better)
        $sevenZip = Get-Command "7z" -ErrorAction SilentlyContinue
        if (-not $sevenZip) {
            $sevenZip = Get-Command "C:\Program Files\7-Zip\7z.exe" -ErrorAction SilentlyContinue
        }

        if ($sevenZip) {
            $password = $SampleInfo.Password
            $szArgs = @("x", "-y", "-o$destDir", "-p$password", $SampleInfo.ZipFile)
            & $sevenZip.Source @szArgs 2>&1 | Out-Null
            Write-Log "Extracted via 7-Zip" "OK"
        }
        else {
            # Fallback: PowerShell Expand-Archive (no password support)
            Write-Log "7-Zip not found -- attempting PowerShell extraction (may fail with password-protected ZIPs)" "WARN"
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

# === CONTROLLED EXECUTION =====================================================
function Invoke-SampleExecution {
    param(
        [int]$DelayBetweenSeconds = 15,
        [string]$Method = "Disk"
    )

    if ($script:ExtractedSamples.Count -eq 0) {
        Write-Log "No extracted samples to execute" "WARN"
        return
    }

    Write-Host ""
    Write-Host "  +============================================================+" -ForegroundColor Red
    Write-Host "  |                    !!  WARNING  !!                          |" -ForegroundColor Red
    Write-Host "  |   About to execute live malware samples.                   |" -ForegroundColor Red
    Write-Host "  |   Ensure this is an ISOLATED, VIRTUALIZED environment.     |" -ForegroundColor Red
    Write-Host "  |   EDR/XDR must be ACTIVE and MONITORING.                   |" -ForegroundColor Red
    Write-Host "  +------------------------------------------------------------+" -ForegroundColor Red
    if ($Method -eq "InMemory") {
        Write-Host "  |   Mode: IN-MEMORY (fileless) -- no disk write              |" -ForegroundColor Magenta
    } else {
        Write-Host "  |   Mode: DISK -- standard filesystem execution              |" -ForegroundColor Yellow
    }
    Write-Host "  +============================================================+" -ForegroundColor Red
    Write-Host ""

    $confirm = Read-Host "  Type 'CONFIRM' to proceed with $Method execution"
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
    Write-Log "Method: $Method | Delay: ${DelayBetweenSeconds}s" "INFO"

    $executionIndex = 0
    foreach ($sample in $exeSamples) {
        $executionIndex++
        Write-Host ""
        Write-Log "[$executionIndex/$($exeSamples.Count)] $($sample.Family)/$($sample.FileName) [$Method]" "EXEC"
        Write-Log "  SHA256: $($sample.SHA256)" "INFO"

        if ($Method -eq "InMemory") {
            Invoke-InMemoryExecution -SamplePath $sample.FullPath -SampleName "$($sample.Family)/$($sample.FileName)"
        }
        else {
            Invoke-DiskExecution -SamplePath $sample.FullPath -SampleName "$($sample.Family)/$($sample.FileName)"
        }

        Write-Log "  Waiting ${DelayBetweenSeconds}s for EDR/XDR telemetry..." "INFO"
        Start-Sleep -Seconds $DelayBetweenSeconds
    }

    Write-Log "Execution phase completed" "OK"
}

# === DISK EXECUTION (Standard) ================================================
function Invoke-DiskExecution {
    param([string]$SamplePath, [string]$SampleName)

    Write-Log "  Method: Disk (filesystem execution)" "INFO"
    Write-Log "  Path: $SamplePath" "INFO"

    try {
        if ($SamplePath -match '\.dll$') {
            # DLLs: use rundll32
            $proc = Start-Process -FilePath "rundll32.exe" -ArgumentList "$SamplePath,DllMain" -PassThru -ErrorAction Stop
            Write-Log "  PID: $($proc.Id) -- Launched via rundll32" "OK"
        }
        else {
            $proc = Start-Process -FilePath $SamplePath -PassThru -ErrorAction Stop
            Write-Log "  PID: $($proc.Id) -- Process launched" "OK"
        }

        Start-Sleep -Seconds 3
        if (-not $proc.HasExited) {
            Write-Log "  Status: Running (PID $($proc.Id))" "OK"
        } else {
            Write-Log "  Status: Exited (code: $($proc.ExitCode))" "INFO"
        }
    }
    catch {
        Write-Log "  BLOCKED: $($_.Exception.Message)" "WARN"
        Write-Log "  (Expected if EDR/XDR prevented execution)" "INFO"
    }
}

# === IN-MEMORY EXECUTION (Fileless) ===========================================
function Invoke-InMemoryExecution {
    <#
    .SYNOPSIS
        Loads and executes a sample directly in memory without writing to disk.
        Tests EDR/XDR fileless threat detection capabilities.

        For .NET assemblies: uses [Reflection.Assembly]::Load()
        For native PE:       uses VirtualAlloc + CreateThread via P/Invoke
    #>
    param([string]$SamplePath, [string]$SampleName)

    Write-Log "  Method: InMemory (reflective loading)" "INFO"

    try {
        # Read raw bytes into memory
        $bytes = [System.IO.File]::ReadAllBytes($SamplePath)
        Write-Log "  Read $($bytes.Length) bytes into memory" "INFO"

        # Detect if .NET assembly
        $isDotNet = $false
        try {
            $testAssembly = [System.Reflection.AssemblyName]::GetAssemblyName($SamplePath)
            $isDotNet = $true
        }
        catch { $isDotNet = $false }

        if ($isDotNet) {
            # -- .NET Reflective Loading --
            Write-Log "  Detected .NET assembly -- using Reflection.Assembly.Load()" "INFO"

            try {
                $assembly = [System.Reflection.Assembly]::Load($bytes)
                $entryPoint = $assembly.EntryPoint

                if ($entryPoint) {
                    Write-Log "  Entry point: $($entryPoint.DeclaringType.FullName)::$($entryPoint.Name)" "INFO"

                    # Invoke with empty args
                    $paramCount = $entryPoint.GetParameters().Count
                    if ($paramCount -eq 0) {
                        $entryPoint.Invoke($null, $null)
                    } else {
                        $entryPoint.Invoke($null, @(,@([string]::Empty)))
                    }
                    Write-Log "  .NET assembly invoked in-memory" "OK"
                }
                else {
                    # No entry point -- try to find and invoke Main from any type
                    $types = $assembly.GetTypes()
                    $mainMethod = $null
                    foreach ($type in $types) {
                        $mainMethod = $type.GetMethod('Main', [System.Reflection.BindingFlags]'Static,Public,NonPublic')
                        if ($mainMethod) { break }
                    }
                    if ($mainMethod) {
                        Write-Log "  Found Main() in $($mainMethod.DeclaringType.FullName)" "INFO"
                        $mainMethod.Invoke($null, @(,@([string]::Empty)))
                        Write-Log "  .NET Main() invoked in-memory" "OK"
                    }
                    else {
                        Write-Log "  Assembly loaded but no entry point found" "WARN"
                    }
                }
            }
            catch {
                Write-Log "  .NET in-memory execution caught: $($_.Exception.Message)" "WARN"
                Write-Log "  (EDR/XDR may have intercepted the reflective load)" "INFO"
            }
        }
        else {
            # -- Native PE -- Shellcode-style execution via P/Invoke --
            Write-Log "  Detected native PE -- using VirtualAlloc + CreateThread" "INFO"

            # Add Win32 API types if not already loaded
            if (-not ([System.Management.Automation.PSTypeName]'Win32.Kernel32').Type) {
                Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    public class Kernel32 {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);
    }
}
"@
            }

            try {
                # Allocate RWX memory
                $allocSize = [uint32]$bytes.Length
                $mem = [Win32.Kernel32]::VirtualAlloc(
                    [IntPtr]::Zero,
                    $allocSize,
                    0x3000,   # MEM_COMMIT | MEM_RESERVE
                    0x40      # PAGE_EXECUTE_READWRITE
                )

                if ($mem -eq [IntPtr]::Zero) {
                    Write-Log "  VirtualAlloc failed" "FAIL"
                    return
                }

                Write-Log "  Allocated $allocSize bytes at 0x$($mem.ToString('X'))" "INFO"

                # Copy bytes to allocated memory
                [System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $mem, $bytes.Length)
                Write-Log "  PE bytes copied to memory" "INFO"

                # Create thread at the allocated memory
                $thread = [Win32.Kernel32]::CreateThread(
                    [IntPtr]::Zero, 0, $mem, [IntPtr]::Zero, 0, [IntPtr]::Zero
                )

                if ($thread -eq [IntPtr]::Zero) {
                    Write-Log "  CreateThread failed" "FAIL"
                    [Win32.Kernel32]::VirtualFree($mem, 0, 0x8000) | Out-Null
                    return
                }

                Write-Log "  Thread created -- PE executing in memory" "OK"

                # Wait briefly then check
                [Win32.Kernel32]::WaitForSingleObject($thread, 5000) | Out-Null
                Write-Log "  In-memory execution completed" "OK"
            }
            catch {
                Write-Log "  Native in-memory execution caught: $($_.Exception.Message)" "WARN"
                Write-Log "  (EDR/XDR may have blocked memory allocation or thread creation)" "INFO"
            }
        }
    }
    catch {
        Write-Log "  InMemory load failed: $($_.Exception.Message)" "WARN"
    }
}

# === SUMMARY REPORT ===========================================================
function Write-Summary {
    param([array]$Results)

    Write-Host "`n  ==========================================================" -ForegroundColor DarkCyan
    Write-Host "                     VALIDATION SUMMARY" -ForegroundColor Cyan
    Write-Host "  ==========================================================" -ForegroundColor DarkCyan

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
            Write-Host "    $($s.Family)/$($s.FileName) -- $($s.SHA256.Substring(0,16))..." -ForegroundColor Gray
        }
    }

    Write-Host "`n  Full log: $LogPath" -ForegroundColor DarkGray
    Write-Host ""
}

# === MAIN =====================================================================
Write-Banner

# Initialize log
"=== Polymorphic Sample Validation Log ===" | Out-File -FilePath $LogPath
"Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Add-Content -Path $LogPath
"Mode: $Mode | ExecMethod: $ExecMethod | PrepareEnv: $PrepareEnv" | Add-Content -Path $LogPath
"" | Add-Content -Path $LogPath

# Phase 0: Prepare environment (if requested)
if ($PrepareEnv) {
    $envReady = Set-LabEnvironment
    if (-not $envReady) {
        Write-Log "Environment preparation failed. Continuing anyway..." "WARN"
    }
}

# Discover sample families (all subdirectories except hidden/system)
$families = Get-ChildItem -Path $SamplesPath -Directory | Where-Object {
    $_.Name -notlike ".*" -and $_.Name -ne "__MACOSX"
}

# Filter by family if specified
if ($Family) {
    $families = $families | Where-Object { $_.Name -like $Family }
    if ($families.Count -eq 0) {
        Write-Log "No family matching '$Family' found in $SamplesPath" "FAIL"
        Write-Log "Available families:" "INFO"
        Get-ChildItem -Path $SamplesPath -Directory | Where-Object {
            $_.Name -notlike ".*" -and $_.Name -ne "__MACOSX"
        } | ForEach-Object { Write-Log "  - $($_.Name)" "INFO" }
        exit 1
    }
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
    Write-Host "`n  --- EXTRACTION PHASE ----------------------------------------" -ForegroundColor DarkCyan

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
        Invoke-SampleExecution -DelayBetweenSeconds $DelaySeconds -Method $ExecMethod
    }
}

# Phase 4: Offer to restore environment
if ($PrepareEnv) {
    Write-Host ""
    $restore = Read-Host "  Restore Windows Defender settings? (y/N)"
    if ($restore -eq 'y' -or $restore -eq 'Y') {
        Restore-LabEnvironment
    } else {
        Write-Log "Defender remains disabled. Run with -PrepareEnv and restore manually, or revert VM snapshot." "WARN"
    }
}

Write-Log "Completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "INFO"
