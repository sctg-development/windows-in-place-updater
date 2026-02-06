<#
in-place-upgrade.ps1

---------------------------------------------
Author: SCTG Development ( Ronan Le Meillat )
License: MIT
Repository: https://github.com/sctg-development/windows-in-place-updater
Version: 0.2 (2026-02-06)
---------------------------------------------

This script provides helper functions to perform in-place upgrades of Windows installations.
It was inspired by https://raw.githubusercontent.com/TheMMC/In-Place_Upgrade_Helper/refs/heads/main/english/In-Place_Upgrade_Helper.bat
#>

# ---------------------------
# Ensure TLS 1.2 is used for web requests
# ---------------------------
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}
catch {
    Write-Error "Outdated operating systems are not supported."
    Exit 1
}

# ---------------------------
# Ensure running elevated
# ---------------------------
<#
.SYNOPSIS
Ensures the script is running with Administrator privileges.

.DESCRIPTION
This function checks if the current PowerShell process has Administrator privileges.
If not, it relaunches the entire script with elevated privileges using UAC (User Access Control).
The original working directory is preserved to ensure relative paths work correctly.
Many operations in this script (registry writes, setup.exe with specific switches) require
administrator privileges and will fail without elevation.

.OUTPUTS
None. If elevation is needed, the function relaunches the script elevated and exits the current process.
If already elevated, the function returns normally.

.NOTES
This function should be called at the very beginning of the script before any privileged operations.
It will trigger a UAC prompt on Windows systems when elevation is required.
#>
function Assert-Elevated {
    $isAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "Relaunching script as Administrator..." -ForegroundColor Yellow
        try { $psExe = (Get-Process -Id $PID -ErrorAction Stop).Path } catch { $psExe = $null }
        if (-not $psExe) {
            if (Get-Command pwsh -ErrorAction SilentlyContinue) { $psExe = (Get-Command pwsh).Source }
            elseif (Get-Command powershell -ErrorAction SilentlyContinue) { $psExe = (Get-Command powershell).Source }
            else { Write-Host "Could not find a PowerShell executable to relaunch the script." -ForegroundColor Red; Exit 1 }
        }
        # Relaunch the same PowerShell executable elevated and ensure the elevated process runs from the same working directory.
        try { $cwd = (Get-Location).ProviderPath } catch { $cwd = $null }
        # Escape single quotes to embed safely in a single-quoted command string
        # We double-up single quotes because we will place the path inside a single-quoted -Command string
        # and the elevated process will parse the string again. This prevents mismatched quoting issues.
        if ($cwd) { $escCwd = $cwd -replace "'", "''" } else { $escCwd = $null }
        $escScript = $PSCommandPath -replace "'", "''"

        # Build a conservative, predictable argument list for the relaunched elevated process.
        # - '-NoProfile' and '-ExecutionPolicy Bypass' reduce differences between environments.
        $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass')
        if ($escCwd) {
            # When the working directory is known, use -Command so we can call Set-Location first.
            # This ensures any relative paths used later in the elevated session resolve the same way
            # as in the original process (important for working-directory-relative downloads and extractions).
            $command = "Set-Location -LiteralPath '$escCwd'; & '$escScript'"
            $argList += '-Command'
            $argList += $command
        }
        else {
            # Fall back to -File when we cannot determine the original working directory. Note that
            # -File will likely start in a system directory (e.g. C:\Windows\System32), so callers
            # should avoid relying on relative paths when this branch is taken.
            $argList += '-File'
            $argList += $PSCommandPath
        }

        # Launch the elevated process and exit this one. We use -Verb RunAs to trigger UAC.
        Start-Process -FilePath $psExe -ArgumentList $argList -Verb RunAs -WindowStyle Maximized
        Exit
    }
}
Assert-Elevated

# ---------------------------
# Maintainer notes
# ---------------------------
# This script is intended to be run interactively with Administrator privileges.
# Key conventions and notes for maintainers:
# - Script-level variables use the `script:` scope so they are accessible across functions.
# - All external tools and artifacts are stored under the repository-local `files\` directory
#   (e.g., `files\aria2c.exe`, `files\7zr.exe`, `files\uup-converter-wimlib.7z`). This keeps the
#   working directory self-contained and makes tests reproducible during development.
# - Network operations use small helper functions (Get-RemoteFile, Test-Hash) and set
#   `User-Agent` headers via `$script:headers` to avoid simple server rejections.
# - The script favors defensive programming: it validates inputs, checks return values,
#   and prints clear error messages followed by a `Wait-Script` pause so users can see failures.
# - When changing behavior that affects file locations, ensure Start-UUPDumpISOBuilder and
#   Expand-UUPConverterWimLib remain consistent about where converter artifacts live.
# - When adding new dependencies, update the hashes and URLs in the global vars near the top
#   and add an installation helper that performs idempotent downloads + verification.

# ---------------------------
# Global variables (script-scoped)
# ---------------------------
# We use the `script:` scope so variables are available across functions in this script. These variables hold the
# user's choices and important state that many functions read and update.
# Maintain these notes when adding or renaming globals:
# - Keep file/tool names in their own variables so they can be checked and re-used consistently.
# - When adding a new dependency, include a checksum variable and a small install helper that
#   downloads into `files\` and verifies the checksum with `Test-Hash`.
# - Avoid hardcoded absolute paths; use $script:currentLocation or Join-Path to build paths.
$script:currentLocation = Get-Location  # the working directory where the script was launched (used as root for outputs)
$script:headers = @{ 'User-Agent' = 'in-place-upgrade/0.1 (+https://github.com/sctg-development/in-place-updater)' } # headers for REST calls
$script:sourcesPath = '.'                           # the path where the installation media is located (e.g. E:\ or C:\temp\iso)
$script:productkey = ''                             # chosen product key string (a KMS / retail key used for pre-install)
$script:editionid = ''                              # edition ID that we may write into the registry for forced upgrade flows
$script:productname = ''                            # human-friendly product name (e.g. 'Windows 10 Pro')
$script:compositioneditionid = ''                   # composition ID for some editions
$script:selectedImageIndex = $null                  # store the chosen ImageIndex (int) after the user selects an image
$script:selectedImageFile = $null                   # store the file (install.wim/install.esd) containing the image
$script:selectedImageName = $null                   # store the display name of the image
$script:uupDumpApiUrl = 'https://api.uupdump.net/'  # UUP Dump API base URL
$script:aria2cFile = 'aria2c.exe'
$script:aria2cUrl = 'https://uupdump.net/misc/aria2c.exe';
$script:aria2cHash = 'b9cd71b275af11b63c33457b0f43f2f2675937070c563e195f223efd7fa4c74b';
$script:7zrFile = '7zr.exe'
$script:7zrUrl = 'https://www.7-zip.org/a/7zr.exe';
$script:7zrHash = '27cbe3d5804ad09e90bbcaa916da0d5c3b0be9462d0e0fb6cb54be5ed9030875';
$script:uupConvertWimLibFile = 'uup-converter-wimlib.7z';
$script:uupConvertWimLibUrl = 'https://uupdump.net/misc/uup-converter-wimlib-v120z.7z';
$script:uupConvertWimLibHash = '9c03f6153c90859882e507cb727b9963f28c8bbf3e6eca51ff7ed286d5267c4c';

# Embedded default ConvertConfig.ini (used when the archive excludes it)
$script:DefaultConvertConfigIni = @'
[convert-UUP]
AutoStart    =1
AddUpdates   =1
Cleanup      =1
ResetBase    =0
NetFx3       =1
StartVirtual =0
wim2esd      =0
wim2swm      =0
SkipISO      =0
SkipWinRE    =0
LCUwinre     =0
LCUmsuExpand =0
UpdtBootFiles=0
ForceDism    =0
RefESD       =0
SkipLCUmsu   =0
SkipEdge     =0
AutoExit     =0
DisableUpdatingUpgrade=0
AddDrivers   =0
Drv_Source   =\Drivers

[Store_Apps]
SkipApps     =0
AppsLevel    =0
StubAppsFull =0
CustomList   =0

[create_virtual_editions]
vUseDism     =1
vAutoStart   =1
vDeleteSource=0
vPreserve    =0
vwim2esd     =0
vwim2swm     =0
vSkipISO     =0
vAutoEditions=
vSortEditions=
'@

# Embedded default CustomAppsList.txt
$script:DefaultCustomAppsList = @'
### This file allows you to customize which Microsoft Store Apps are installed
### during the UUP to ISO conversion process.
###
### For changes done to this file to be applied, the CustomList option in the
### ConvertConfig.ini file needs to be set to 1.
### 
### This customization is supported only in builds 22563 and later.

### Choose the wanted apps from below by removing # prefix

### Common Apps / Client editions all
Microsoft.WindowsStore_8wekyb3d8bbwe
Microsoft.StorePurchaseApp_8wekyb3d8bbwe
Microsoft.SecHealthUI_8wekyb3d8bbwe
Microsoft.DesktopAppInstaller_8wekyb3d8bbwe
# Microsoft.Windows.Photos_8wekyb3d8bbwe
# Microsoft.WindowsCamera_8wekyb3d8bbwe
# Microsoft.WindowsNotepad_8wekyb3d8bbwe
# Microsoft.Paint_8wekyb3d8bbwe
# Microsoft.WindowsTerminal_8wekyb3d8bbwe
# MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy
# Microsoft.WindowsAlarms_8wekyb3d8bbwe
# Microsoft.WindowsCalculator_8wekyb3d8bbwe
# Microsoft.WindowsMaps_8wekyb3d8bbwe
# Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe
# Microsoft.ScreenSketch_8wekyb3d8bbwe
# microsoft.windowscommunicationsapps_8wekyb3d8bbwe
# Microsoft.People_8wekyb3d8bbwe
# Microsoft.BingNews_8wekyb3d8bbwe
# Microsoft.BingWeather_8wekyb3d8bbwe
# Microsoft.MicrosoftSolitaireCollection_8wekyb3d8bbwe
# Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe
# Microsoft.WindowsFeedbackHub_8wekyb3d8bbwe
# Microsoft.GetHelp_8wekyb3d8bbwe
# Microsoft.Getstarted_8wekyb3d8bbwe
# Microsoft.Todos_8wekyb3d8bbwe
# Microsoft.XboxSpeechToTextOverlay_8wekyb3d8bbwe
# Microsoft.XboxGameOverlay_8wekyb3d8bbwe
# Microsoft.XboxIdentityProvider_8wekyb3d8bbwe
# Microsoft.PowerAutomateDesktop_8wekyb3d8bbwe
# Microsoft.549981C3F5F10_8wekyb3d8bbwe
# MicrosoftCorporationII.QuickAssist_8wekyb3d8bbwe
# MicrosoftCorporationII.MicrosoftFamily_8wekyb3d8bbwe
# Clipchamp.Clipchamp_yxz26nhyzhsrt
# Microsoft.OutlookForWindows_8wekyb3d8bbwe
# MicrosoftTeams_8wekyb3d8bbwe
# Microsoft.Windows.DevHome_8wekyb3d8bbwe
# Microsoft.BingSearch_8wekyb3d8bbwe
# Microsoft.ApplicationCompatibilityEnhancements_8wekyb3d8bbwe
# MicrosoftWindows.CrossDevice_cw5n1h2txyewy
# MSTeams_8wekyb3d8bbwe
# Microsoft.MicrosoftPCManager_8wekyb3d8bbwe
# Microsoft.StartExperiencesApp_8wekyb3d8bbwe
# Microsoft.WidgetsPlatformRuntime_8wekyb3d8bbwe

### Media Apps / Client non-N editions
# Microsoft.ZuneMusic_8wekyb3d8bbwe
# Microsoft.ZuneVideo_8wekyb3d8bbwe
# Microsoft.YourPhone_8wekyb3d8bbwe
# Microsoft.WindowsSoundRecorder_8wekyb3d8bbwe
# Microsoft.GamingApp_8wekyb3d8bbwe
# Microsoft.XboxGamingOverlay_8wekyb3d8bbwe
# Microsoft.Xbox.TCUI_8wekyb3d8bbwe

### Media Codecs / Client non-N editions, Team edition
# Microsoft.WebMediaExtensions_8wekyb3d8bbwe
# Microsoft.RawImageExtension_8wekyb3d8bbwe
# Microsoft.HEIFImageExtension_8wekyb3d8bbwe
# Microsoft.HEVCVideoExtension_8wekyb3d8bbwe
# Microsoft.VP9VideoExtensions_8wekyb3d8bbwe
# Microsoft.WebpImageExtension_8wekyb3d8bbwe
# Microsoft.DolbyAudioExtensions_8wekyb3d8bbwe
# Microsoft.AVCEncoderVideoExtension_8wekyb3d8bbwe
# Microsoft.MPEG2VideoExtension_8wekyb3d8bbwe
# Microsoft.AV1VideoExtension_8wekyb3d8bbwe

### Surface Hub Apps / Team edition
# Microsoft.Whiteboard_8wekyb3d8bbwe
# microsoft.microsoftskydrive_8wekyb3d8bbwe
# Microsoft.MicrosoftTeamsforSurfaceHub_8wekyb3d8bbwe
# MicrosoftCorporationII.MailforSurfaceHub_8wekyb3d8bbwe
# Microsoft.MicrosoftPowerBIForWindows_8wekyb3d8bbwe
# Microsoft.SkypeApp_kzf8qxf38zg5c
# Microsoft.Office.Excel_8wekyb3d8bbwe
# Microsoft.Office.PowerPoint_8wekyb3d8bbwe
# Microsoft.Office.Word_8wekyb3d8bbwe
'@

# ---------------------------
# File retrieval functions
# ---------------------------
<#
.SYNOPSIS
Checks if a helper file exists in the files\ directory.

.DESCRIPTION
Tests whether a file with the given name exists in the local 'files\' subdirectory.
This function is used to verify the presence of downloaded helper tools before use.

.PARAMETER File
The name of the file to check (without path).

.OUTPUTS
Boolean. Returns $true if the file exists and is a leaf (not a directory), $false otherwise.
#>
function Test-FileExistence {
    param (
        [String]$File
    )

    # Returns true when a file with the given name exists under files\ and is a leaf (not a directory).
    return Test-Path -PathType Leaf -Path "files\$File"
}

<#
.SYNOPSIS
Downloads a remote file to the files\ directory.

.DESCRIPTION
Attempts to download a file from a given URL and saves it to files\<File>.
Display console output during download. This function throws on failure; callers
should catch errors and provide appropriate error messages to the user.

.PARAMETER File
The destination filename (without path; will be saved to files\$File).

.PARAMETER Url
The remote URL to download from.

.OUTPUTS
None. On success, the file is written to files\$File. On failure, throws an error.
#>
function Get-RemoteFile {
    param (
        [String]$File,
        [String]$Url
    )

    # Download a remote URL to files\<File>. This function throws on failure and relies on callers
    # to display useful messages and to handle retry/backoff if desired.
    Write-Host -BackgroundColor Black -ForegroundColor Yellow "Downloading ${File}..."
    Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile "files\$File" -ErrorAction Stop
}

<#
.SYNOPSIS
Verifies the SHA256 hash of a file.

.DESCRIPTION
Computes the SHA256 hash of files\<File> and compares it to the expected hash value.
Returns a boolean indicating whether the hash matches. This is used to verify the integrity
of downloaded files and protect against tampering.

.PARAMETER File
The filename in the files\ directory to verify.

.PARAMETER Hash
The expected SHA256 hash as a lowercase hex string.

.OUTPUTS
Boolean. Returns $true if the hash matches, $false otherwise.
#>
function Test-Hash {
    param (
        [String]$File,
        [String]$Hash
    )

    # Compute SHA256 on files\<File> and compare to the expected (hex lowercase) hash string.
    # Returns boolean; callers treat a false result as an integrity failure and bail out.
    Write-Host -BackgroundColor Black -ForegroundColor Cyan "Verifying ${File}..."

    $fileHash = (Get-FileHash -Path "files\$File" -Algorithm SHA256 -ErrorAction Stop).Hash
    return ($fileHash.ToLower() -eq $Hash)
}

# ----------------------------
# Function to install aria2c.exe if not present
# ----------------------------
<#
.SYNOPSIS
Ensures aria2c.exe is installed and verified.

.DESCRIPTION
Checks if aria2c.exe exists in files\ and has the correct SHA256 hash.
If not present or hash mismatch, downloads it from the configured URL and verifies integrity.
Aria2c is used for parallel, reliable downloads of UUP file sets from UUP Dump.
This function is idempotent: if the file exists with correct hash, returns immediately.

.OUTPUTS
Boolean. Returns $true if aria2c is ready, $false if download or verification failed.
#>
function Install-Aria2c {
    if ((Test-FileExistence -File $script:aria2cFile) -and (Test-Hash -File $script:aria2cFile -Hash $script:aria2cHash)) {
        Write-Host -BackgroundColor Black -ForegroundColor Green "Aria2c is ready."
        return $true
    }

    # Ensure the files directory exists to hold downloaded helpers
    if (-not (Test-Path -PathType Container -Path "files")) {
        $null = New-Item -Path "files" -ItemType Directory
    }

    # Suppress progress in automated contexts
    $ProgressPreference = 'SilentlyContinue'

    try {
        Get-RemoteFile -File $script:aria2cFile -Url $script:aria2cUrl
    }
    catch {
        Write-Host "Failed to download $($script:aria2cFile)"
        Write-Host $_
        return $false
    }

    # Verify SHA256 to protect users from tampered binaries; fail hard if mismatch
    if (-not (Test-Hash -File $script:aria2cFile -Hash $script:aria2cHash)) {
        Write-Error "$($script:aria2cFile) appears to be tampered with"
        return $false
    }
    return $true
}

# ----------------------------
# Function to install 7zr.exe if not present
# ----------------------------
<#
.SYNOPSIS
Ensures 7zr.exe is installed and verified.

.DESCRIPTION
Checks if 7zr.exe exists in files\ and has the correct SHA256 hash.
If not present or hash mismatch, downloads it from the configured URL and verifies integrity.
7zr is a command-line utility for extracting and manipulating 7z archives, used to extract
the UUP converter archive. This function is idempotent: if the file exists with correct hash,
returns immediately.

.OUTPUTS
Boolean. Returns $true if 7zr is ready, $false if download or verification failed.
#>
function Install-7zr {
    # If the helper already exists and its integrity is verified, short-circuit and return success.
    if ((Test-FileExistence -File $script:7zrFile) -and (Test-Hash -File $script:7zrFile -Hash $script:7zrHash)) {
        Write-Host -BackgroundColor Black -ForegroundColor Green "7zr is ready."
        return $true
    }

    # Ensure the 'files' directory exists — place all downloaded helpers here to keep the workspace tidy and testable.
    if (-not (Test-Path -PathType Container -Path "files")) {
        $null = New-Item -Path "files" -ItemType Directory
    }

    # Avoid cluttering interactive output with progress bars; maintainers can change this for debugging.
    $ProgressPreference = 'SilentlyContinue'

    try {
        # Download the 7zr binary into files\7zr.exe
        Get-RemoteFile -File $script:7zrFile -Url $script:7zrUrl
    }
    catch {
        Write-Host "Failed to download $($script:7zrFile)"
        Write-Host $_
        return $false
    }

    # Always verify the SHA256 checksum to avoid running a tampered binary. Fail early if mismatch.
    if (-not (Test-Hash -File $script:7zrFile -Hash $script:7zrHash)) {
        Write-Error "$($script:7zrFile) appears to be tampered with"
        return $false
    }
    return $true
}

# ----------------------------
# Function to install UUP Converter WimLib if not present
# ----------------------------
<#
.SYNOPSIS
Ensures the UUP Converter WimLib archive is installed and verified.

.DESCRIPTION
Checks if the UUP converter archive (uup-converter-wimlib.7z) exists in files\ and has the correct SHA256 hash.
If not present or hash mismatch, downloads it from the configured URL and verifies integrity.
The converter is used to transform downloaded UUP files into a Windows installation ISO.
This function is idempotent: if the file exists with correct hash, returns immediately.

.OUTPUTS
Boolean. Returns $true if UUP Converter WimLib is ready, $false if download or verification failed.
#>
function Install-UUPConverterWimLib {
    # The UUP converter archive is relatively large; check whether it's already present and valid first.
    if ((Test-FileExistence -File $script:uupConvertWimLibFile) -and (Test-Hash -File $script:uupConvertWimLibFile -Hash $script:uupConvertWimLibHash)) {
        Write-Host -BackgroundColor Black -ForegroundColor Green "UUP Converter WimLib is ready."
        return $true
    }

    # Ensure download directory exists; keeping tools under 'files\' keeps the workspace self-contained.
    if (-not (Test-Path -PathType Container -Path "files")) {
        $null = New-Item -Path "files" -ItemType Directory
    }

    $ProgressPreference = 'SilentlyContinue'

    try {
        # Download the archive into files\uup-converter-wimlib.7z
        Get-RemoteFile -File $script:uupConvertWimLibFile -Url $script:uupConvertWimLibUrl
    }
    catch {
        Write-Host "Failed to download $($script:uupConvertWimLibFile)"
        Write-Host $_
        return $false
    }

    # Strong integrity check: verify SHA256 before attempting extraction or running any included scripts.
    if (-not (Test-Hash -File $script:uupConvertWimLibFile -Hash $script:uupConvertWimLibHash)) {
        Write-Error "$($script:uupConvertWimLibFile) appears to be tampered with"
        return $false
    }
    return $true
}

#----------------------------
# Function to expand UUP Converter WimLib using 7zr
#----------------------------
<#
.SYNOPSIS
Extracts the UUP Converter WimLib archive.

.DESCRIPTION
Extracts files from the uup-converter-wimlib.7z archive to the current directory, excluding
ConvertConfig.ini and CustomAppsList.txt (to allow site-specific versions).
The converter contains helper scripts and tools needed to transform UUP files into an ISO.
Must be called after the converter archive has been downloaded and verified.

.OUTPUTS
Boolean. Returns $true if extraction succeeded, $false if 7zr is unavailable or extraction failed.
#>
function Expand-UUPConverterWimLib {
    if (-not (Install-7zr)) { return $false }
    if (-not (Test-FileExistence -File $script:uupConvertWimLibFile)) { Write-Error "UUP Converter WimLib archive not found."; return $false }

    try {
        # Exclude ConvertConfig.ini and CustomAppsList.txt so site maintainers can provide local versions
        & "files\$($script:7zrFile)" "-x!ConvertConfig.ini" "-x!CustomAppsList.txt" -y x "files\$($script:uupConvertWimLibFile)" > $null
        Write-Host "UUP Converter WimLib expanded successfully."
        return $true
    }
    catch {
        Write-Host "Failed to expand UUP Converter WimLib."
        Write-Host $_
        return $false
    }
}

#----------------------------
# Get JSON list of ids from UUP Dump API
#----------------------------
<#
.SYNOPSIS
Retrieves the list of available UUP Dump IDs from the UUP Dump API.

.DESCRIPTION
Fetches and parses the JSON response from the UUP Dump API listid.php endpoint.
Returns the list of available UUP builds that can be downloaded and converted to ISO.
The API response structure may vary; this function handles common shapes gracefully.

.OUTPUTS
An array of objects containing UUP build information, or $null if the API fails or returns an unexpected format.
#>
function Get-UUPDumpIds {
    $url = $script:uupDumpApiUrl + 'listid.php'
    try {
        # Some servers reject requests without a User-Agent; provide a minimal one.
        $headers = $script:headers 
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers -ErrorAction Stop

        # The API historically returns an object where 'response.builds' contains the array of IDs. However,
        # the API shape has changed in the past and may sometimes return null or a different structure. To be robust
        # we check the common shape and return $null when unexpected so callers can handle absence gracefully.
        if ($null -ne $response.response -and $null -ne $response.response.builds) {
            return $response.response.builds
        }
        else {
            # Unknown or empty response; callers will treat no IDs as an empty list.
            return $null
        }

        # Unknown format
        Write-Host "Warning: unexpected API response structure from $url" -ForegroundColor Yellow
        return $null
    }
    catch {
        # Network errors or parsing errors are surfaced to the user; callers should handle a returned $null.
        Write-Host "Error fetching UUP Dump IDs: $_" -ForegroundColor Red
        return $null
    }
}

#----------------------------
# Filter UUP Dump for returning only titles starting with "Windows 10", "Windows 11" or "Windows Server"
#----------------------------
<#
.SYNOPSIS
Filters UUP Dump IDs by OS type and architecture.

.DESCRIPTION
Retrieves all available UUP Dump IDs, then filters them by:
- Operating system name (keeps only Windows 10, Windows 11, or Windows Server)
- Architecture (matches the current system architecture)
- Excludes Insider and Preview builds to avoid unstable pre-releases
The results are sorted by title for consistent presentation to the user.

.OUTPUTS
An array of filtered UUP IDs sorted by title, or empty array if none match.
#>
function Get-FilteredUUPDumpIds {
    $arch = Get-SystemArchitecture
    $allIds = Get-UUPDumpIds
    if (-not $allIds) { return @() }
    $filteredIds = @()

    foreach ($item in $allIds) {
        # Defensive parsing: the API sometimes includes entries with missing or unexpected fields,
        # so skip any entry that does not have a title to avoid runtime errors.
        #
        # Filtering policy:
        #  - Only include titles that start with 'Windows 10', 'Windows 11' or 'Windows Server' (case-insensitive)
        #    to avoid unrelated entries returned by the API.
        #  - Exclude any titles that contain 'insider' or 'preview' (case-insensitive) to prevent selecting
        #    unstable pre-release builds for ISO creation unless the maintainer explicitly changes this.
        #  - Ensure the UUP set matches the system architecture reported by Get-SystemArchitecture.
        if ($null -ne $item.title -and ($item.title -match '^(?i:Windows 10|Windows 11|Windows Server)') -and -not ($item.title -match '(?i:insider|preview)') -and ($item.arch -eq $arch)) {
            $filteredIds += $item
        }
    }

    # Sort results by title (case-insensitive) before returning so callers receive an ordered list
    return ($filteredIds | Sort-Object { ($_.title -as [string]).ToLower() })
}

#----------------------------
# Second level filter to return only id matching the current Windows kind (Client/Server)
#----------------------------
<#
.SYNOPSIS
Filters UUP Dump IDs by Windows kind (Client vs Server).

.DESCRIPTION
Takes the already-filtered UUP IDs and further filters them based on the current system's Windows kind.
If the system is Client, keeps only Windows 10/11 builds. If the system is Server, keeps only Windows Server builds.
This prevents users from accidentally downloading Server builds on a Client OS.

.OUTPUTS
An array of filtered UUP IDs matching the system's Windows kind, or empty array if none match.
#>
function Get-FilteredUUPDumpIdsByWindowsKind {
    $kind = Get-WindowsKind
    $allFilteredIds = Get-FilteredUUPDumpIds
    if (-not $allFilteredIds) { return @() }
    $finalFilteredIds = @()

    foreach ($item in $allFilteredIds) {
        if ($kind -eq 'Client' -and $item.title -match '^(?i:Windows 10|Windows 11)') {
            $finalFilteredIds += $item
        }
        elseif ($kind -eq 'Server' -and $item.title -match '^(?i:Windows Server)') {
            $finalFilteredIds += $item
        }
    }

    return $finalFilteredIds
}

#----------------------------
# Function for retrieving a list of editions available for a given UUP Dump ID and language
#----------------------------
<#
.SYNOPSIS
Retrieves the list of Windows editions available for a given UUP Dump ID and language.

.DESCRIPTION
Queries the UUP Dump API to get the available editions (Pro, Home, Enterprise, etc.) for a specific UUP ID
and language combination. Returns a semicolon-separated string of edition identifiers (e.g., 'pro;home;enterprise').

.PARAMETER uupId
The UUP Dump ID (uuid) to query.

.PARAMETER languageTag
The language tag (e.g., 'en-US', 'fr-FR') to use.

.OUTPUTS
A semicolon-separated string of edition identifiers, or $null if the API fails or returns an unexpected format.
#>
function Get-UUPDumpEditions {
    param (
        [string]$uupId,
        [string]$languageTag
    )
    # Convert parameters to lower case to avoid language-tag case issues when forming requests.
    $uupId = $uupId.ToLower()
    $languageTag = $languageTag.ToLower()
    $url = $script:uupDumpApiUrl + "listeditions.php?id=$uupId&lang=$languageTag"
    try {
        # Some servers reject requests without a User-Agent; provide a minimal one.
        $headers = $script:headers 
        Write-Host "Fetching edition list for UUP ID '$uupId' and language '$languageTag' from UUP Dump API..." -ForegroundColor Cyan
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers -ErrorAction Stop

        # The API historically returns an object with 'response.editionList'. Each item can be comma-separated
        # with additional metadata. We take the first part (before the comma), normalize it to lower case, and
        # return a semicolon-separated list like: 'pro;home;enterprise'. The caller encodes this for the URL.
        if ($null -ne $response.response -and $null -ne $response.response.editionList) {
            # Return only the first token of each list item and concatenate with ';'
            $ret = ($response.response.editionList | ForEach-Object { $_.Split(',')[0].ToLower() }) -join ';'
            return $ret
        }
        else {
            return $null
        }

        # Unknown format
        Write-Host "Warning: unexpected API response structure from $url" -ForegroundColor Yellow
        return $null
    }
    catch {
        Write-Host "Error fetching UUP Dump list editions : $_" -ForegroundColor Red
        return $null
    }
}

#----------------------------
# Function to download a UUP set and construct an ISO using UUP Dump (download + convert)
#----------------------------
<#
.SYNOPSIS
Downloads a Windows build from UUP Dump and converts it to a bootable ISO.

.DESCRIPTION
This is a complex workflow that:
1. Queries UUP Dump API for available builds
2. Prompts user to select a build and language
3. Retrieves the builder configuration file from UUP Dump
4. Downloads all required files using aria2
5. Runs the UUP converter to create an installation ISO
6. Automatically mounts the ISO and makes it available as an installation source

Requires at least 10 GB free disk space. Downloads may take considerable time depending on
network speed and selected build size.

.OUTPUTS
None. On success, sets $script:LastCreatedISO to the path of the created ISO file.
On failure, outputs error messages and returns without creating an ISO.

.NOTES
This is a long-running operation. The converter displays its own progress output in a separate window.
#>
function Start-UUPDumpISOBuilder {
    param()

    try {
        # Require at least 10 GiB free on current drive to ensure there is enough space for the UUP files
        # and for the temporary files created during conversion.
        $minBytes = 10 * 1024 * 1024 * 1024
        $cwdDrive = (Get-Item -Path ".").PSDrive
        if (-not $cwdDrive -or -not $cwdDrive.Free) { Write-Host "Could not determine free space on current drive." -ForegroundColor Yellow; Wait-Script; return }
        if ($cwdDrive.Free -lt $minBytes) { Write-Host "At least 10 GB free space is required. Available: $([Math]::Round($cwdDrive.Free/1GB,2)) GB" -ForegroundColor Red; Wait-Script; return }

        # Get candidate UUP sets filtered by Windows kind (Client vs Server) and by architecture
        $ids = Get-FilteredUUPDumpIdsByWindowsKind
        if (-not $ids -or $ids.Count -eq 0) { Write-Host "No UUP Dump IDs available for your Windows kind." -ForegroundColor Yellow; Wait-Script; return }

        # Present a stable, numbered list to the user and permit selecting by index. This avoids typing long IDs.
        Write-Host "Available UUP sets:" -ForegroundColor Cyan
        $i = 0
        foreach ($it in $ids) {
            $i++
            $title = ($it.title -as [string])
            $uuid = ($it.uuid)
            Write-Host "$i) $title  [id: $uuid]"
        }

        # Validate the user's selection strictly: only a numeric index within the shown range is accepted.
        $sel = Read-Host -Prompt "Enter the number to use (or 'c' to cancel)"
        if ($sel -match '^[cC]$') { Write-Host "Cancelled."; return }
        if (-not ($sel -match '^\d+$' -and [int]$sel -ge 1 -and [int]$sel -le $ids.Count)) { Write-Host "Invalid selection."; Wait-Script; return }

        $chosen = $ids[[int]$sel - 1]
        $uupId = ($chosen.uuid)
        if (-not $uupId) { Write-Host "Selected item does not contain an id." -ForegroundColor Red; Wait-Script; return }

        # Language selection (default to the system language). Note: Get-WindowsLanguageTag may return an array;
        # if so, use the first entry as a sensible default.
        $langDefault = Get-WindowsLanguageTag
        if ($langDefault -is [array]) { $langDefault = $langDefault[0] }
        $langInput = Read-Host -Prompt "Enter language tag (e.g. en-US) [default: $langDefault]"
        if ([string]::IsNullOrWhiteSpace($langInput)) { $lang = $langDefault } else { $lang = $langInput }

        # Retrieve the edition tokens for the UUP set and language. This helper returns a semicolon-separated
        # list (e.g. 'pro;home;enterprise'); encode it for inclusion in the get.php URL.
        $editions = Get-UUPDumpEditions -uupId $uupId -languageTag $lang
        if (-not $editions) { Write-Host "Could not retrieve edition list for selected id and language." -ForegroundColor Red; Wait-Script; return }
        $editionParam = $editions -replace ';', '%3B'

        # Build the UUP Dump request URL that instructs it to return an aria2 script for fetching files.
        $url = "https://uupdump.net/get.php?id=$uupId&pack=$lang&edition=$editionParam&aria2=2"

        # Ensure prerequisites available
        if (-not (Install-Aria2c)) { Write-Host "aria2 is required but could not be installed." -ForegroundColor Red; Wait-Script; return }
        if (-not (Install-UUPConverterWimLib)) { Write-Host "UUP converter archive missing and could not be downloaded." -ForegroundColor Red; Wait-Script; return }
        if (-not (Expand-UUPConverterWimLib)) { Write-Host "Failed to expand UUP converter." -ForegroundColor Red; Wait-Script; return }

        # Create default ConvertConfig.ini and CustomAppsList.txt in the working directory if they were excluded from the archive
        try {
            $ccPath = Join-Path $script:currentLocation 'ConvertConfig.ini'
            if (-not (Test-Path -LiteralPath $ccPath)) {
                Set-Content -LiteralPath $ccPath -Value $script:DefaultConvertConfigIni -Encoding UTF8 -ErrorAction Stop
                Write-Host "Created ConvertConfig.ini in $($script:currentLocation)" -ForegroundColor Green
            }
            else { Write-Host "ConvertConfig.ini already present at $ccPath; leaving it unchanged." -ForegroundColor Cyan }

            $appsPath = Join-Path $script:currentLocation 'CustomAppsList.txt'
            if (-not (Test-Path -LiteralPath $appsPath)) {
                Set-Content -LiteralPath $appsPath -Value $script:DefaultCustomAppsList -Encoding UTF8 -ErrorAction Stop
                Write-Host "Created CustomAppsList.txt in $($script:currentLocation)" -ForegroundColor Green
            }
            else { Write-Host "CustomAppsList.txt already present at $appsPath; leaving it unchanged." -ForegroundColor Cyan }
        }
        catch {
            Write-Host "Warning: could not create default config/app files: $_" -ForegroundColor Yellow
        }

        $aria2Script = "files\aria2_script.$($uupId).txt"
        $destDir = "UUPs"

        # Retrieve an aria2 download script from UUP Dump. The returned file contains the individual
        # file URLs and aria2 options (we write it into files\aria2_script.<id>.txt).
        Write-Host "Retrieving aria2 script for the UUP set from $url ..." -ForegroundColor Cyan
        try {
            & "files\$($script:aria2cFile)" --no-conf --async-dns=false --console-log-level=warn --log-level=info -o $aria2Script --allow-overwrite=true --auto-file-renaming=false $url
        }
        catch { Write-Host "Failed to retrieve aria2 script: $_" -ForegroundColor Red; Wait-Script; return }

        # Verify the aria2 script was created and that UUP Dump did not return an error payload
        if (-not (Test-Path $aria2Script)) { Write-Host "Aria2 script was not created." -ForegroundColor Red; Wait-Script; return }
        $content = Get-Content -Path $aria2Script -ErrorAction SilentlyContinue
        if ($content -match '#UUPDUMP_ERROR:') { $err = ($content | Select-String '#UUPDUMP_ERROR:' | ForEach-Object { $_.Line }); Write-Host "UUPDump error: $err" -ForegroundColor Red; Wait-Script; return }

        # Download the UUP files. Use a retry loop with backoff to handle transient network or server issues.
        if (-not (Test-Path -Path $destDir)) { New-Item -Path $destDir -ItemType Directory | Out-Null }

        $downloadAttempts = 4
        $attempt = 1
        $downloadOk = $false
        while ($attempt -le $downloadAttempts -and -not $downloadOk) {
            Write-Host "Downloading the UUP set... (attempt $attempt/$downloadAttempts)" -ForegroundColor Cyan
            # Aria2 options:
            # -x, -s, -j: connection/thread tuning
            # -R: resume-download/relative options
            # --continue=true: resume partial downloads if present
            # -d: destination directory, -i: read input file (the aria2 script)
            & "files\$($script:aria2cFile)" --no-conf --async-dns=false --console-log-level=warn --log-level=info -x16 -s16 -j5 -R --max-tries=5 --continue=true --conditional-get=false -d $destDir -i $aria2Script
            $exit = $LASTEXITCODE
            if ($exit -eq 0) { $downloadOk = $true; break }
            Write-Host "aria2 failed (exit code $exit)." -ForegroundColor Yellow
            if ($attempt -lt $downloadAttempts) {
                # Exponential-ish backoff capped at 60 seconds
                $wait = [Math]::Min(60, 5 * $attempt)
                Write-Host "Retrying in $wait seconds..." -ForegroundColor Cyan
                Start-Sleep -Seconds $wait
            }
            $attempt++
        }

        if (-not $downloadOk) { Write-Host "aria2 failed to download the UUP set after $downloadAttempts attempts." -ForegroundColor Red; Wait-Script; return }

        # Prepare and run converter
        # The converter's entry point `convert-UUP.cmd` should be present in the working directory root
        # because Expand-UUPConverterWimLib places the converter files alongside this script.
        $convCmd = Join-Path $script:currentLocation 'convert-UUP.cmd'
        if (-not (Test-Path -LiteralPath $convCmd -PathType Leaf)) { Write-Host "convert-UUP.cmd not found in working directory. Ensure the converter was extracted correctly." -ForegroundColor Red; Wait-Script; return }
        Write-Host "Starting conversion with UUP converter ($convCmd). The converter will display progress in its console." -ForegroundColor Cyan
        # Launch the converter and wait for it to exit. Note: on many Windows systems this will open a new console window for the converter process.
        Start-Process -FilePath $convCmd -WorkingDirectory $script:currentLocation -NoNewWindow -Wait
        if ($LASTEXITCODE -ne 0) { Write-Host "convert-UUP failed or returned non-zero exit code." -ForegroundColor Red; Wait-Script; return }

        # Attempt to find the ISO produced by the converter. Prefer an ISO whose name includes the build
        # number from the selected UUP set (e.g., 26100.3114.*.ISO). For builds that include a sub-build (e.g. 26100.3114)
        # also accept filenames where the parts are separated by other tokens, such as 26100.*.3114.*.ISO.
        # Fall back to the most recently modified ISO in the working directory if no build-based filename is found.
        try {
            $script:LastCreatedISO = $null
            if ($null -ne $chosen -and $null -ne $chosen.build) {
                $build = $chosen.build.ToString()
                $patterns = @()
                # Primary pattern: file name starts with the full build token
                $patterns += "$($build)*.iso"

                # If the build contains a dot (major.minor), also look for patterns where the parts are separated
                # by additional tokens: e.g. "26100.*.3114*.iso"
                if ($build -match '\.') {
                    $parts = $build -split '\.'
                    if ($parts.Count -ge 2) {
                        $patterns += "$($parts[0]).*.$($parts[1])* .iso" -replace ' ', ''
                        # Also tolerate a looser pattern without the explicit dot between parts (e.g. 26100*3114*.iso)
                        $patterns += "$($parts[0])*$($parts[1])* .iso" -replace ' ', ''
                    }
                }

                foreach ($pat in $patterns) {
                    $found = Get-ChildItem -Path $script:currentLocation -Filter $pat -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                    if ($found) { $script:LastCreatedISO = $found.FullName; break }
                }
            }
            if (-not $script:LastCreatedISO) {
                # Fallback: pick the newest ISO in the working directory
                $found = Get-ChildItem -Path $script:currentLocation -Filter '*.iso' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                if ($found) { $script:LastCreatedISO = $found.FullName }
            }
            if ($script:LastCreatedISO) { Write-Host "Located ISO: $($script:LastCreatedISO)" -ForegroundColor Green } else { Write-Host "No ISO found in $($script:currentLocation) after conversion." -ForegroundColor Yellow }
        }
        catch { Write-Host "Warning: error while searching for created ISO: $_" -ForegroundColor Yellow }

        Write-Host "UUP set downloaded and conversion started. Check the converter console for progress." -ForegroundColor Green
    }
    catch { Write-Host "Error during UUP ISO build: $_" -ForegroundColor Red; Wait-Script; return }
}

#----------------------------
# Function for returning x86, amd64 or arm64 architecture string based on system info
#----------------------------
<#
.SYNOPSIS
Detects the system architecture.

.DESCRIPTION
Determines the processor architecture of the running system.
Returns normalized architecture strings: 'amd64', 'x86', 'arm64', or 'arm'.
The result is used to filter available UUP Dump builds to compatible architectures.

.OUTPUTS
String. One of: 'amd64', 'x86', 'arm64', 'arm', or the original system-reported value if not recognized.
#>
function Get-SystemArchitecture {
    try {
        # RuntimeInformation::OSArchitecture returns values like X64, X86, Arm, Arm64
        $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLower()
        switch ($arch) {
            'x64' { return 'amd64' }
            'x86' { return 'x86' }
            'arm64' { return 'arm64' }
            'arm' { return 'arm' }
            default { return $arch }
        }
    }
    catch {
        # Fallback to CIM query (older systems)
        $arch = (Get-CimInstance -Class Win32_OperatingSystem).OSArchitecture
        if ($arch -match 'ARM64' -or $arch -match 'arm64') { return 'arm64' }
        elseif ($arch -match '64' -or $arch -match 'x64' -or $arch -match 'X64') { return 'amd64' }
        elseif ($arch -match '86' -or $arch -match 'x86') { return 'x86' }
        elseif ($arch -match 'arm' -or $arch -match 'ARM') { return 'arm' }
        else { return ($arch -as [string]).ToLower() } # fallback to a normalized string
    }
}

#----------------------------
# Function for returning current Windows kind either Client or Server
#----------------------------
<#
.SYNOPSIS
Detects the Windows edition kind (Client or Server).

.DESCRIPTION
Queries the Win32_OperatingSystem WMI class to determine whether the current Windows installation
is a Client edition (ProductType=1) or a Server edition (ProductType other than 1).
This is used to filter available UUP Dump builds to compatible OS types.

.OUTPUTS
String. Either 'Client' or 'Server', or 'Unknown' if detection fails.
#>
function Get-WindowsKind {
    try {
        $os = Get-CimInstance -Class Win32_OperatingSystem
        if ($os.ProductType -eq 1) {
            return 'Client'
        }
        else {
            return 'Server'
        }
    }
    catch {
        Write-Host "Error determining Windows kind: $_" -ForegroundColor Red
        return 'Unknown'
    }
}

#----------------------------
# Function to get current Windows language tag (e.g. en-US)
#----------------------------
<#
.SYNOPSIS
Retrieves the current system language tag(s).

.DESCRIPTION
Queries the Win32_OperatingSystem WMI class to get the system's configured language(s).
Language tags are returned in lowercase (e.g., 'en-us', 'fr-fr') for easier matching with the UUP Dump API.

.OUTPUTS
String or array of strings representing the system language tags, or $null if detection fails.
#>
function Get-WindowsLanguageTag {
    try {
        $langList = Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty MUILanguages
        return $langList.ToLower() # return in lower case for easier matching with UUP Dump API
    }
    catch {
        Write-Host "Error determining Windows language tag: $_" -ForegroundColor Red
        return $null
    }
}



# ---------------------------
# Editions map (lookup table)
# ---------------------------
<#
.SYNOPSIS
Populates the global editions lookup table.

.DESCRIPTION
Initializes the $editions global hashtable with Windows edition information.
Each entry contains:
- K: Default KMS/retail product key for the edition
- E: Internal EditionID used by Windows
- EName: Human-friendly edition name for display
- C: CompositionEditionID (used by some editions)
This table is used to present choices to the user and to set registry values during forced upgrades.

.OUTPUTS
None. Populates the global $editions variable.
#>
function Set-Editions {
    $global:editions = @{}
    $editions['1'] = @{K = 'YTMG3-N6DKC-DKB77-7M9GH-8HVX7'; E = 'Core'; EName = 'Windows 10 Home'; C = 'Core' }
    $editions['2'] = @{K = 'VK7JG-NPHTM-C97JM-9MPGT-3V66T'; E = 'Professional'; EName = 'Windows 10 Pro'; C = 'Enterprise' }
    $editions['3'] = @{K = 'DXG7C-N36C4-C4HTG-X4T3X-2YV77'; E = 'ProfessionalWorkstation'; EName = 'Windows 10 Pro for Workstations'; C = 'Enterprise' }
    $editions['4'] = @{K = 'XGVPP-NMH47-7TTHJ-W3FW7-8HV2C'; E = 'Enterprise'; EName = 'Windows 10 Enterprise'; C = 'Enterprise' }
    $editions['5'] = @{K = '8PTT6-RNW4C-6V7J2-C2D3X-MHBPB'; E = 'ProfessionalEducation'; EName = 'Windows 10 Pro Education'; C = 'Enterprise' }
    $editions['6'] = @{K = 'YNMGQ-8RYV3-4PGQ3-C8XTP-7CFBY'; E = 'Education'; EName = 'Windows 10 Education'; C = 'Enterprise' }
    $editions['7'] = @{K = 'CPWHC-NT2C7-VYW78-DHDB2-PG3GK'; E = 'ServerRdsh'; EName = 'Windows 10 Enterprise multi-session'; C = 'Enterprise' }
    $editions['8'] = @{K = 'XQQYW-NFFMW-XJPBH-K8732-CKFFD'; E = 'IoTEnterprise'; EName = 'Windows 10 IoT Enterprise'; C = 'Enterprise' }
    $editions['9'] = @{K = 'BT79Q-G7N6G-PGBYW-4YWX6-6F4BT'; E = 'CoreSingleLanguage'; EName = 'Windows 10 Home Single Language'; C = 'Core' }
    $editions['10'] = @{K = 'KY7PN-VR6RX-83W6Y-6DDYQ-T6R4W'; E = 'CloudEdition'; EName = 'Windows 10 SE'; C = 'Enterprise' }
    $editions['11'] = @{K = '4CPRK-NM3K3-X6XXQ-RXX86-WXCHW'; E = 'CoreN'; EName = 'Windows 10 Home N'; C = 'CoreN' }
    $editions['12'] = @{K = '2B87N-8KFHP-DKV6R-Y2C8J-PKCKT'; E = 'ProfessionalN'; EName = 'Windows 10 Pro N'; C = 'EnterpriseN' }
    $editions['13'] = @{K = 'WYPNQ-8C467-V2W6J-TX4WX-WT2RQ'; E = 'ProfessionalWorkstationN'; EName = 'Windows 10 Pro N for Workstations'; C = 'EnterpriseN' }
    $editions['14'] = @{K = 'GJTYN-HDMQY-FRR76-HVGC7-QPF8P'; E = 'ProfessionalEducationN'; EName = 'Windows 10 Pro Education N'; C = 'EnterpriseN' }
    $editions['15'] = @{K = '84NGF-MHBT6-FXBX8-QWJK7-DRR8H'; E = 'EducationN'; EName = 'Windows 10 Education N'; C = 'EnterpriseN' }
    $editions['16'] = @{K = '3V6Q6-NQXCX-V8YXR-9QCYV-QPFCT'; E = 'EnterpriseN'; EName = 'Windows 10 Enterprise N'; C = 'EnterpriseN' }
    $editions['17'] = @{K = 'K9VKN-3BGWV-Y624W-MCRMQ-BHDCD'; E = 'CloudEditionN'; EName = 'Windows 10 SE N'; C = 'EnterpriseN' }
    $editions['18'] = @{K = 'M7XTQ-FN8P6-TTKYV-9D4CC-J462D'; E = 'EnterpriseS'; EName = 'Windows 10 Enterprise LTSC 2021'; C = 'EnterpriseS' }
    $editions['19'] = @{K = 'QPM6N-7J2WJ-P88HH-P3YRH-YY74H'; E = 'IoTEnterpriseS'; EName = 'Windows 10 IoT Enterprise LTSC 2021'; C = 'EnterpriseS' }
    $editions['20'] = @{K = '2D7NQ-3MDXF-9WTDT-X9CCP-CKD8V'; E = 'EnterpriseSN'; EName = 'Windows 10 Enterprise N LTSC 2021'; C = 'EnterpriseSN' }
    $editions['21'] = @{K = 'M7XTQ-FN8P6-TTKYV-9D4CC-J462D'; E = 'EnterpriseS'; EName = 'Windows 11 Enterprise LTSC 2024'; C = 'EnterpriseS' }
    $editions['22'] = @{K = 'KBN8V-HFGQ4-MGXVD-347P6-PDQGT'; E = 'IoTEnterpriseS'; EName = 'Windows 10 IoT Enterprise LTSC 2024'; C = 'EnterpriseS' }
    $editions['23'] = @{K = '92NFX-8DJQP-P6BBQ-THF9C-7CG2H'; E = 'EnterpriseSN'; EName = 'Windows 10 Enterprise N LTSC 2024'; C = 'EnterpriseSN' }
    $editions['24'] = @{K = 'N979K-XWD77-YW3GB-HBGH6-D32MH'; E = 'IoTEnterpriseSK'; EName = 'Windows 10 IoT Enterprise Subscription LTSC 2024'; C = 'EnterpriseS' }
    $editions['25'] = @{K = 'VDYBN-27WPP-V4HQT-9VMD4-VMK7H'; E = 'ServerStandard'; EName = 'Windows Server 2022 Standard'; C = 'ServerStandard' }
    $editions['26'] = @{K = 'WX4NM-KYWYW-QJJR4-XV3QB-6VM33'; E = 'ServerDatacenter'; EName = 'Windows Server 2022 Datacenter'; C = 'ServerDatacenter' }
    $editions['27'] = @{K = 'DPNXD-67YY9-WWFJJ-RYH99-RM832'; E = 'ServerStandard'; EName = 'Windows Server 2025 Standard'; C = 'ServerStandard' }
    $editions['28'] = @{K = 'CNFDQ-2BW8H-9V4WM-TKCPD-MD2QF'; E = 'ServerDatacenter'; EName = 'Windows Server 2025 Datacenter'; C = 'ServerDatacenter' }
}
Set-Editions

# Simple helper that pauses until the user presses Enter. Useful in interactive scripts so the user has time to read messages.
<#
.SYNOPSIS
Pauses the script until the user presses Enter.

.DESCRIPTION
Displays a prompt "Press Enter to continue..." and blocks until the user presses Enter.
Used to give the user time to read error messages or status information in interactive scripts.

.OUTPUTS
None.
#>
function Wait-Script { Read-Host -Prompt "Press Enter to continue..." > $null }

# ---------------------------
# Validation helpers
# ---------------------------
<#
.SYNOPSIS
Validates that a file is a genuine Windows setup.exe.

.DESCRIPTION
Performs strict validation of a setup.exe file:
- Verifies the file exists
- Checks the Authenticode digital signature (must be 'Valid')
- Checks the FileDescription field matches known Windows setup patterns
This defensive approach helps avoid accidentally launching untrusted setup binaries.

.PARAMETER file
Path to the file to validate.

.OUTPUTS
Boolean. Returns $true if the file passes all validation checks, $false otherwise.
#>
function Test-SetupExeValid {
    param([string]$file)

    # Validate that the provided path points to a file and that it looks like a genuine Windows setup binary.
    # This function is intentionally strict to avoid launching untrusted setup binaries.
    if (-not (Test-Path $file -PathType Leaf)) { return $false }

    # Known substrings that appear in Windows setup FileDescription fields in supported builds.
    $allowedDescPatterns = @('Microsoft® Windows® Operating System', 'Windows Installer', 'Windows Setup', 'Installation et configuration de Windows')

    # Check the Authenticode signature where possible; a 'Valid' signature is required for acceptance.
    try { $sig = Get-AuthenticodeSignature -FilePath $file -ErrorAction SilentlyContinue } catch { $sig = $null }

    # Extract file description (language/OS localized) to help avoid false positives.
    try { $desc = (Get-Item $file -ErrorAction SilentlyContinue).VersionInfo.FileDescription } catch { $desc = $null }

    # Require a strictly 'Valid' signature and a known description substring.
    if (-not $sig -or $sig.Status -ne 'Valid') { return $false }
    if (-not $desc) { return $false }
    if ($allowedDescPatterns | Where-Object { $desc -match $_ }) { return $true }
    return $false
} 

<#
.SYNOPSIS
Validates that a sources directory contains Windows installation files.

.DESCRIPTION
Checks whether the specified directory contains at least one install.wim or install.esd file,
which are required for Windows installation. Used to detect valid installation media.

.PARAMETER dir
Path to the directory to validate.

.OUTPUTS
Boolean. Returns $true if at least one install.wim or install.esd file is found, $false otherwise.
#>
function Test-SourcesValid {
    param([string]$dir)
    if (-not (Test-Path $dir -PathType Container)) { return $false }
    $files = Get-ChildItem -Path $dir -File -Include 'install.wim', 'install.esd' -ErrorAction SilentlyContinue
    return ($files.Count -gt 0)
}

<#
.SYNOPSIS
Normalizes a path string to a consistent format.

.DESCRIPTION
Converts user input paths into a standardized format:
- Single drive letters (e.g., 'E') become 'E:\'
- Drive letters with colon (e.g., 'E:') become 'E:\'
- Paths without trailing backslash get one added
This ensures consistent path handling regardless of how the user enters the path.

.PARAMETER p
The path string to normalize.

.OUTPUTS
String. The normalized path, or the original string if normalization fails.
#>
function ConvertTo-SourcesPath {
    param([string]$p)
    if ($null -eq $p -or ([string]::IsNullOrWhiteSpace($p))) { return $p }
    try {
        $r = Resolve-Path -LiteralPath $p -ErrorAction SilentlyContinue
        if ($r) { $pp = $r.ProviderPath; if ($pp -match '^[A-Za-z]:$') { $pp = $pp + '\\' }; return $pp }
    }
    catch {}
    if ($p -match '^[A-Za-z]$') { return ($p + ':\') }
    if ($p -match '^[A-Za-z]:$') { return ($p + '\') }
    if ($p -match '^[A-Za-z]:\\') { if (-not $p.EndsWith('\')) { return $p + '\' } else { return $p } }
    return $p
}

# ---------------------------
# Image listing helpers
# ---------------------------
<#
.SYNOPSIS
Retrieves the list of available Windows images from an installation source.

.DESCRIPTION
Searches for install.wim, install.esd, or install.swm files in the 'sources' subdirectory.
For each file found, enumerates the contained images and returns their metadata.
Prefers using Get-WindowsImage cmdlet (from Windows Image PowerShell module) when available;
falls back to parsing DISM output for systems without the module.
Returns an array of objects with ImageIndex, ImageName, and File properties.

.PARAMETER sourcesBase
Base path to the installation source (the parent of the 'sources' directory).

.OUTPUTS
Array of PSCustomObjects with properties: ImageIndex (int), ImageName (string), File (string path).
Returns empty array if no sources found.
#>
function Get-ImagesFromSources {
    param([string]$sourcesBase)
    if (-not $sourcesBase) { return @() }
    $s = Join-Path $sourcesBase 'sources'
    $results = @()

    # This helper tries two approaches to enumerate images inside an install.* file:
    # 1) Use Get-WindowsImage when the image module is available (preferred since it returns structured data).
    # 2) Fallback to parsing the output of dism.exe when the module is not present (text parsing is brittle
    #    but ensures the script remains functional on systems without the Windows Image PowerShell module).
    foreach ($ext in @('install.wim', 'install.esd', 'install.swm')) {
        $path = Join-Path $s $ext
        if (-not (Test-Path $path)) { continue }
        try {
            $imgs = Get-WindowsImage -ImagePath $path -ErrorAction Stop | Select-Object ImageIndex, ImageName
            foreach ($img in $imgs) { $results += [pscustomobject]@{ ImageIndex = $img.ImageIndex; ImageName = $img.ImageName; File = $path } }
            continue
        }
        catch {
            try {
                # dism.exe returns human-readable text; this block extracts Index/Name pairs from its output.
                $dout = & dism.exe /Get-WimInfo "/WimFile:${path}" 2>&1
                if ($LASTEXITCODE -eq 0 -and $dout) {
                    $current = $null
                    foreach ($line in $dout) {
                        if ($line -match 'Index\s*:\s*(\d+)') { $current = @{ ImageIndex = [int]$matches[1]; ImageName = '' ; File = $path } }
                        if ($line -match 'Name\s*:\s*(.+)') { if ($current) { $current.ImageName = $matches[1].Trim(); $results += [pscustomobject]$current; $current = $null } }
                    }
                }
            }
            catch { }
        }
    }
    return $results
} 

<#
.SYNOPSIS
Displays available Windows images to the user.

.DESCRIPTION
Retrieves the list of available images from the sources directory and displays them
in a human-readable format with index, name, and source file information.

.PARAMETER sourcesBase
Base path to the installation source (the parent of the 'sources' directory).

.OUTPUTS
None. Output is written to the console.
#>
function Show-AvailableImages {
    param([string]$sourcesBase)
    $images = Get-ImagesFromSources -sourcesBase $sourcesBase
    if (-not $images -or $images.Count -eq 0) { Write-Host "No install.* files found in $sourcesBase`\sources" -ForegroundColor Yellow; return }
    Write-Host "Available images:" -ForegroundColor Cyan
    foreach ($img in $images) { Write-Host "Index: $($img.ImageIndex) - $($img.ImageName)  [file: $($img.File)]" }
}

<#
.SYNOPSIS
Prompts the user to select a Windows image from available sources.

.DESCRIPTION
Displays a list of available images with their indices and names, then prompts the user
to select one by entering its ImageIndex. Returns the selected image object or $null if canceled.

.PARAMETER sourcesBase
Base path to the installation source (the parent of the 'sources' directory).

.OUTPUTS
A PSCustomObject with ImageIndex, ImageName, and File properties. Returns $null if no image selected or not found.
#>
function Select-ImageFromSources {
    param([string]$sourcesBase)
    $images = Get-ImagesFromSources -sourcesBase $sourcesBase
    if (-not $images -or $images.Count -eq 0) { Write-Host "No images found in $sourcesBase" -ForegroundColor Yellow; return $null }
    Write-Host "Available images (enter ImageIndex to choose):" -ForegroundColor Cyan
    foreach ($img in $images) { Write-Host "Index: $($img.ImageIndex) - $($img.ImageName)  [file: $($img.File)]" }
    $sel = Read-Host -Prompt 'Enter ImageIndex to install (or c to cancel)'
    if ($sel -match '^[cC]$') { return $null }
    if ($sel -match '^\d+$') {
        $num = [int]$sel
        foreach ($img in $images) { if ($img.ImageIndex -eq $num) { return $img } }
    }
    Write-Host "Invalid selection." -ForegroundColor Yellow
    return $null
}

# ---------------------------
# Edition detection helper
# ---------------------------
<#
.SYNOPSIS
Attempts to auto-detect a Windows edition from an image name.

.DESCRIPTION
Uses multiple strategies to map a WIM/ESD image name to a known edition:
1. Exact match on the EName field (case-insensitive)
2. Keyword preference (server, datacenter, standard, home, education) to avoid false matches
3. Substring/token matching (less strict)
Returns the edition object from the $editions table or $null if no match is found.
This function helps avoid manual edition selection when auto-detection is reliable.

.PARAMETER imageName
The image name from the WIM/ESD file.

.OUTPUTS
Hashtable with edition information (K, E, EName, C properties), or $null if no match found.
#>
function Find-EditionByImageName {
    param([string]$imageName)
    if (-not $imageName) { return $null }
    $iname = $imageName.ToLower()

    # Matching strategy, ordered from most to least strict:
    # 1) Exact match on EName (case-insensitive)
    # 2) Keyword-based preferences to distinguish server/datacenter/standard/home/education
    # 3) Containment/token matching (less strict substring matches)
    # This ordering reduces false positives and helps pick the most likely edition automatically.
    foreach ($kv in $editions.GetEnumerator()) {
        $info = $kv.Value
        if ($iname -eq $info.EName.ToLower()) { return $info }
    }

    foreach ($kv in $editions.GetEnumerator()) {
        $info = $kv.Value
        $ename = $info.EName.ToLower()
        if ($iname -match 'server' -and $ename -match 'server') { return $info }
        if ($iname -match 'datacenter' -and $ename -match 'datacenter') { return $info }
        if ($iname -match 'standard' -and $ename -match 'standard') { return $info }
        if ($iname -match '\bhome\b' -and $ename -match '\bhome\b') { return $info }
        if ($iname -match 'education' -and $ename -match 'education') { return $info }
    }

    foreach ($kv in $editions.GetEnumerator()) {
        $info = $kv.Value
        $ename = $info.EName.ToLower()
        if ($iname -match [Regex]::Escape($ename)) { return $info }
        $tokens = $ename -split '\\s+' | Where-Object { $_.Length -gt 3 }
        foreach ($t in $tokens) { if ($iname -match [Regex]::Escape($t)) { return $info } }
    }
    return $null
} 

<#
.SYNOPSIS
Allows the user to select an image and automatically detects its edition.

.DESCRIPTION
Guides the user through selecting a Windows image from the sources directory.
Attempts to auto-detect the corresponding edition from the image name.
If auto-detection fails, presents the full editions table for manual selection.
Populates script-scoped variables with the selection: selectedImageIndex, selectedImageFile, selectedImageName,
productkey, editionid, productname, and compositioneditionid.

.PARAMETER sourcesBase
Base path to the installation source (the parent of the 'sources' directory).

.OUTPUTS
Boolean. Returns $true if selection succeeded, $false if selection was canceled or failed.
#>
function SelectImageAndAutoSetEdition {
    param([string]$sourcesBase)
    # Allow the user to pick an image from the sources and attempt to auto-select a matching edition.
    $img = Select-ImageFromSources -sourcesBase $sourcesBase
    if (-not $img) { Write-Host "No image selected." -ForegroundColor Yellow; return $false }
    Write-Host "Selected image: Index $($img.ImageIndex) - $($img.ImageName)" -ForegroundColor Cyan

    # Save selection to script-scoped variables for use by Start-Upgrade and other flows.
    $script:selectedImageIndex = $img.ImageIndex
    $script:selectedImageFile = $img.File
    $script:selectedImageName = $img.ImageName

    # Try to map the image name to a known edition automatically. If mapping is successful,
    # Set-Edition persists associated product keys and edition IDs for later installation flows.
    $ed = Find-EditionByImageName -imageName $img.ImageName
    if ($ed) {
        Set-Edition -Key $ed.K -EditionID $ed.E -ProductName $ed.EName -CompositionEditionID $ed.C
        return $true
    }

    # If auto-detection failed, present the full edition list for manual selection and persist the choice.
    Write-Host "Could not auto-detect an edition for image: $($img.ImageName)" -ForegroundColor Yellow
    Write-Host "Please pick an edition from the list:" -ForegroundColor Cyan
    foreach ($k in ($editions.Keys | Sort-Object { [int]$_ })) { $e = $editions[$k]; Write-Host "$k) $($e.EName)" }
    $sel = Read-Host -Prompt 'Enter the number of the edition (or c to cancel)'
    if ($sel -match '^\d+$' -and $editions.ContainsKey($sel)) {
        $e = $editions[$sel]
        Set-Edition -Key $e.K -EditionID $e.E -ProductName $e.EName -CompositionEditionID $e.C
        return $true
    }
    Write-Host "Edition not selected." -ForegroundColor Yellow
    return $false
} 

<#
.SYNOPSIS
Records the selected edition information globally.

.DESCRIPTION
Persists the chosen edition's information into script-scoped global variables
for use by upgrade workflows. Sets productkey, editionid, productname, and compositioneditionid.
Also displays the selection to the user and prompts them to press Enter.

.PARAMETER Key
The product key for the edition.

.PARAMETER EditionID
The internal EditionID (e.g., 'Professional', 'Enterprise').

.PARAMETER ProductName
The human-friendly product name (e.g., 'Windows 10 Pro').

.PARAMETER CompositionEditionID
The CompositionEditionID value (used by some editions).

.OUTPUTS
None. Sets global variables and displays confirmation to the user.
#>
function Set-Edition {
    param($Key, $EditionID, $ProductName, $CompositionEditionID)
    # Persist the chosen edition information into script-scoped globals so other flows (Start-Upgrade, Start-ForcedUpgrade)
    # can access the pre-installation key and edition identifiers without re-prompting the user.
    $script:productkey = $Key
    $script:editionid = $EditionID
    $script:productname = $ProductName
    $script:compositioneditionid = $CompositionEditionID
    Write-Host "Selected edition: $ProductName" -ForegroundColor Green
    Wait-Script
} 

<#
.SYNOPSIS
Launches Windows setup in standard mode.

.DESCRIPTION
Starts setup.exe with minimal switches, allowing the user to proceed interactively.
Setup will automatically detect and use the appropriate image and edition from the sources.
This is the simplest upgrade path for end users.

.OUTPUTS
None. Launches setup.exe and then calls Exit, terminating the script.
#>
function Start-BoringUpgrade {
    # Launch setup.exe in the simplest, user-driven mode. We pass a few recommended switches:
    # - /eula accept : automatically accept the EULA to avoid an interactive prompt.
    # - /telemetry disable : attempt to reduce telemetry during setup when supported.
    # - /priority normal : keep default priority.
    # - /resizerecoverypartition enable : allow setup to resize/create recovery partitions as required.
    $setup = Join-Path $script:sourcesPath 'setup.exe'
    if (-not (Test-Path $setup)) { Write-Host "setup.exe not found in $script:sourcesPath" -ForegroundColor Red; Wait-Script; return }
    Write-Host "Launching setup (standard mode)..." -ForegroundColor Cyan
    Start-Process -FilePath $setup -ArgumentList '/eula accept', '/telemetry disable', '/priority normal', '/resizerecoverypartition enable'
    Exit
} 

<#
.SYNOPSIS
Launches Windows setup with a pre-installation product key.

.DESCRIPTION
Starts setup.exe with the selected product key passed via the /pkey switch.
If a specific image index was selected by the user, passes it via /imageindex to ensure
the desired image is used. This allows forcing upgrade to a specific edition.

.OUTPUTS
None. Launches setup.exe and then calls Exit, terminating the script.
#>
function Start-Upgrade {
    # Launch setup with a pre-installation product key to force upgrade into the selected edition.
    # Note: passing /pkey makes Setup apply the provided key during the install; ensure the chosen key
    # is appropriate for the selected edition.
    if ([string]::IsNullOrWhiteSpace($script:productkey)) { Write-Host "Please select an edition first!" -ForegroundColor Yellow; Wait-Script; return }
    $setup = Join-Path $script:sourcesPath 'setup.exe'
    if (-not (Test-Path $setup)) { Write-Host "setup.exe not found in $script:sourcesPath" -ForegroundColor Red; Wait-Script; return }
    Write-Host "Launching setup with pre-installation key..." -ForegroundColor Cyan

    $startArgs = @('/eula accept', '/telemetry disable', '/priority normal', '/resizerecoverypartition enable', '/pkey', $script:productkey)
    if ($null -ne $script:selectedImageIndex -and ($null -ne $script:selectedImageIndex -as [int])) {
        # When a specific image index is selected by the user, pass it explicitly to Setup to ensure the desired image is used.
        $startArgs += '/imageindex'
        $startArgs += [string]$script:selectedImageIndex
        Write-Host "Passing image index: $($script:selectedImageIndex) to setup.exe" -ForegroundColor Cyan
    }

    Start-Process -FilePath $setup -ArgumentList $startArgs
    Exit
}

<#
.SYNOPSIS
Performs a forced upgrade by modifying the registry before launching setup.

.DESCRIPTION
WARNING: This is a dangerous operation. Writes EditionID, ProductName, and CompositionEditionID
into HKLM to trick Windows Setup into thinking another edition is installed.
Setup will upgrade to the selected edition, bypassing checks that would normally prevent
downgrades or unsupported edition changes.
Only use this for testing or automation when you fully understand the consequences.
Requires explicit user confirmation before proceeding.

.OUTPUTS
None. Modifies registry, launches setup.exe, and then calls Exit, terminating the script.
#>
function Start-ForcedUpgrade {
    # Forced upgrade is dangerous: it writes EditionID/ProductName into HKLM to trick Setup into thinking
    # another edition is installed. Only use this when you understand the consequences (testing/automation scenarios).
    if ([string]::IsNullOrWhiteSpace($script:productkey)) { Write-Host "Please select an edition first!" -ForegroundColor Yellow; Wait-Script; return }
    Write-Host "Warning: forced upgrade. This modifies the registry to make Setup think another edition is installed." -ForegroundColor Yellow
    $null = Read-Host -Prompt "Press Enter to continue or Ctrl+C to cancel"
    Write-Host "Writing registry entries..." -ForegroundColor Cyan
    try {
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'EditionID' -Value $script:editionid -Force
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'ProductName' -Value $script:productname -Force
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'CompositionEditionID' -Value $script:compositioneditionid -Force
        $wowPath = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion'
        if (Test-Path $wowPath) {
            Set-ItemProperty -Path $wowPath -Name 'EditionID' -Value $script:editionid -Force
            Set-ItemProperty -Path $wowPath -Name 'ProductName' -Value $script:productname -Force
            Set-ItemProperty -Path $wowPath -Name 'CompositionEditionID' -Value $script:compositioneditionid -Force
        }
        Write-Host "Registry updated." -ForegroundColor Green
    }
    catch { Write-Host "Registry write error: $_" -ForegroundColor Red; Wait-Script; return }

    $setup = Join-Path $script:sourcesPath 'setup.exe'
    if (-not (Test-Path $setup)) { Write-Host "setup.exe not found in $script:sourcesPath" -ForegroundColor Red; Wait-Script; return }
    Write-Host "Launching setup with pre-installation key (forced)..." -ForegroundColor Cyan
    Start-Process -FilePath $setup -ArgumentList '/eula accept', '/telemetry disable', '/priority normal', '/resizerecoverypartition enable', '/pkey', $script:productkey
    Exit
} 

<#
.SYNOPSIS
Changes the Windows product key on the running system.

.DESCRIPTION
Uses slmgr.vbs to install a new product key on the running system.
This does not start setup; it only configures the key the current OS will use for activation.
Requires administrator privileges. The operation is performed non-interactively via cscript.exe.

.OUTPUTS
None. Executes slmgr and displays status to the user.
#>
function Set-ProductKey {
    # Change the product key on the running system using slmgr (scripted via cscript). This operation does not
    # start setup; it only sets the key the running system will use for activation. It requires administrative rights.
    if ([string]::IsNullOrWhiteSpace($script:productkey)) { Write-Host "No key selected." -ForegroundColor Yellow; Wait-Script; return }
    Write-Host "Attempting to change product key via slmgr..." -ForegroundColor Cyan
    $slmgr = Join-Path $env:SystemRoot 'System32\slmgr.vbs'
    if (Test-Path $slmgr) {
        # Use cscript to execute the VBS with a single non-interactive call and wait for completion.
        Start-Process -FilePath 'cscript.exe' -ArgumentList "//nologo `"$slmgr`" /ipk $($script:productkey)" -NoNewWindow -Wait
        Write-Host "slmgr command executed." -ForegroundColor Green
    }
    else { Write-Host "Could not find slmgr.vbs" -ForegroundColor Red }
    Wait-Script
} 

# ---------------------------
# ADPrep helpers
# ---------------------------
<#
.SYNOPSIS
Runs the Active Directory forest preparation utility.

.DESCRIPTION
Executes adprep /forestprep from the Windows installation sources.
This updates the Active Directory schema to support a new Windows version.
WARNING: High-impact operation that affects the entire AD forest.
Must be run on the Schema Master with Enterprise Admin privileges.
Requires explicit user confirmation before proceeding.

.PARAMETER sourcesBase
Base path to the installation source (the parent of the 'support\adprep' directory).
Defaults to $script:sourcesPath if not provided.

.OUTPUTS
None. Executes adprep and displays status to the user.

.NOTES
ADPrep operations should only be run as part of a planned Windows upgrade with proper testing.
#>
function Start-ADPrepForestPrep {
    param([string]$sourcesBase)

    # Coerce sourcesBase to a string and fallback to the script global if not provided.
    # ADPrep operations affect the Active Directory schema and domain configuration — these are
    # high-impact operations and should be performed only with proper planning and admin rights.
    $sb = if ($sourcesBase) { [string]$sourcesBase } elseif ($script:sourcesPath) { [string]$script:sourcesPath } else { '' }
    if (-not $sb) { Write-Host "Sources base path not set. Please set sourcesPath first." -ForegroundColor Yellow; Wait-Script; return }

    # Build candidate paths safely (one Join-Path call per candidate to avoid passing arrays to Join-Path)
    $adprepCandidates = @()
    $adprepCandidates += Join-Path -Path $sb -ChildPath 'support\adprep\adprep.exe'
    $adprepCandidates += Join-Path -Path $sb -ChildPath 'support\adprep\adprep32.exe'

    $adprep = $adprepCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $adprep) { Write-Host "adprep.exe not found under $sb\support\adprep" -ForegroundColor Red; Wait-Script; return }

    Write-Host "About to run: $adprep /forestprep" -ForegroundColor Cyan
    Write-Host "Note: /forestprep must be run on the Schema Master with ENTERPRISE admin rights." -ForegroundColor Yellow
    $confirm = Read-Host -Prompt "Run adprep /forestprep now? (y/N)"
    if ($confirm -notmatch '^[Yy]') { Write-Host "Cancelled." -ForegroundColor Yellow; Wait-Script; return }

    try {
        # Use the call operator (&) so the program runs in the same console and outputs are visible.
        & $adprep '/forestprep'
        Write-Host "adprep /forestprep finished." -ForegroundColor Green
    }
    catch {
        Write-Host "adprep execution error: $_" -ForegroundColor Red
    }
    Wait-Script
} 

<#
.SYNOPSIS
Runs the Active Directory domain preparation utility.

.DESCRIPTION
Executes adprep /domainprep from the Windows installation sources.
This updates the domain configuration to support a new Windows version.
Should be run after /forestprep completes. Typically requires Domain Admin privileges.
Requires explicit user confirmation before proceeding.

.PARAMETER sourcesBase
Base path to the installation source (the parent of the 'support\adprep' directory).
Defaults to $script:sourcesPath if not provided.

.OUTPUTS
None. Executes adprep and displays status to the user.

.NOTES
ADPrep operations should only be run as part of a planned Windows upgrade with proper testing.
#>
function Start-ADPrepDomainPrep {
    param([string]$sourcesBase)

    $sb = if ($sourcesBase) { [string]$sourcesBase } elseif ($script:sourcesPath) { [string]$script:sourcesPath } else { '' }
    if (-not $sb) { Write-Host "Sources base path not set. Please set sourcesPath first." -ForegroundColor Yellow; Wait-Script; return }

    $adprepCandidates = @()
    $adprepCandidates += Join-Path -Path $sb -ChildPath 'support\adprep\adprep.exe'
    $adprepCandidates += Join-Path -Path $sb -ChildPath 'support\adprep\adprep32.exe'

    $adprep = $adprepCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $adprep) { Write-Host "adprep.exe not found under $sb\support\adprep" -ForegroundColor Red; Wait-Script; return }

    Write-Host "About to run: $adprep /domainprep" -ForegroundColor Cyan
    Write-Host "Note: /domainprep should be run after /forestprep and typically on a Domain Admin account." -ForegroundColor Yellow
    $confirm = Read-Host -Prompt "Run adprep /domainprep now? (y/N)"
    if ($confirm -notmatch '^[Yy]') { Write-Host "Cancelled." -ForegroundColor Yellow; Wait-Script; return }

    try {
        & $adprep '/domainprep'
        Write-Host "adprep /domainprep finished." -ForegroundColor Green
    }
    catch {
        Write-Host "adprep execution error: $_" -ForegroundColor Red
    }
    Wait-Script
}

<#
.SYNOPSIS
Interactive menu for source path selection and ISO building.

.DESCRIPTION
Guides the user through selecting an installation source via three methods:
1. Manual path entry: User provides a path directly
2. Drive scanning: Script scans local drives for setup.exe or sources folder
3. UUP Dump: Downloads and converts a Windows build into ISO, then mounts it
After selection, optionally displays available images in the sources.
Populates $script:sourcesPath with the selected path.

.PARAMETER initialChoice
Optional. If provided, skips the initial menu and uses this choice ('1', '2', or '3').
Useful for chaining from other menus.

.PARAMETER showImages
Optional. Boolean. If $true (default), displays available images after path selection.

.OUTPUTS
None. Sets $script:sourcesPath and displays information to the user.
#>
function Set-SourcesPathInteractive {
    param([string]$initialChoice, [bool]$showImages = $true)

    # Interactive helper to set `sourcesPath`.
    # Options:
    # 1) Enter a path manually (validated for setup.exe or a sources folder)
    # 2) Scan local drives for candidate media (validates presence of setup.exe or install.wim/esd)
    # 3) Create an ISO using UUP Dump (downloads and runs the converter)
    if (-not $initialChoice) {
        Write-Host "Current installation media path: $($script:sourcesPath)" -ForegroundColor Cyan
        Write-Host "Choose an option:"
        Write-Host "1) Enter a path manually"
        Write-Host "2) Scan drives to find 'setup.exe' or a 'sources' folder (validated)"
        Write-Host "3) Create an ISO from UUP Dump (download & convert)"
    }
    $opt = if ($initialChoice) { $initialChoice } else { Read-Host -Prompt 'Option (1/2/3)' }
    switch ($opt) {
        '1' {
            $p = Read-Host -Prompt "Enter the path (e.g. F:\ or D:\unpackedISO\ )"
            if ([string]::IsNullOrWhiteSpace($p)) { Write-Host "No path entered." -ForegroundColor Yellow; Wait-Script; return }
            try { $resolvedObj = Resolve-Path -LiteralPath $p -ErrorAction Stop; $resolved = $resolvedObj.ProviderPath } catch { Write-Host "Path not found." -ForegroundColor Red; Wait-Script; return }
            $setupFile = Join-Path $resolved 'setup.exe'; $sourcesDir = Join-Path $resolved 'sources'
            $okSetup = Test-SetupExeValid -file $setupFile; $okSources = Test-SourcesValid -dir $sourcesDir
            if ($okSetup -or $okSources) {
                $script:sourcesPath = ConvertTo-SourcesPath $resolved
                Write-Host "sourcesPath set to: $($script:sourcesPath)" -ForegroundColor Green
                if ($showImages) { Show-AvailableImages -sourcesBase $script:sourcesPath }
                Wait-Script; return
            }
            if ((Test-Path $setupFile) -and -not $okSetup) {
                Write-Host "Found setup.exe but it did not pass validation (signature/description)." -ForegroundColor Yellow
                try { $sig = Get-AuthenticodeSignature -FilePath $setupFile -ErrorAction Stop } catch { $sig = $null }
                if ($sig) { Write-Host "Signature status: $($sig.Status) - Signer: $($sig.SignerCertificate.Subject)" -ForegroundColor Yellow }
                try { $desc = (Get-Item $setupFile -ErrorAction Stop).VersionInfo.FileDescription } catch { $desc = $null }
                Write-Host "File description: $($desc -or '<none>')" -ForegroundColor Yellow
                $confirm = Read-Host -Prompt "Use this path anyway? (y/N)"
                if ($confirm -match '^[Yy]') { $script:sourcesPath = ConvertTo-SourcesPath $resolved; if ($showImages) { Show-AvailableImages -sourcesBase $script:sourcesPath }; Wait-Script; return } else { Wait-Script; return }
            }
            if ((Test-Path $sourcesDir) -and -not $okSources) {
                Write-Host "Found 'sources' folder but no install.wim/install.esd present." -ForegroundColor Yellow
                $confirm = Read-Host -Prompt "Set this path anyway? (y/N)"
                if ($confirm -match '^[Yy]') { $script:sourcesPath = ConvertTo-SourcesPath $resolved; if ($showImages) { Show-AvailableImages -sourcesBase $script:sourcesPath }; Wait-Script; return } else { Wait-Script; return }
            }
            Write-Host "No valid setup.exe or 'sources' folder found in $resolved" -ForegroundColor Yellow
            $confirm = Read-Host -Prompt "Set this path anyway? (y/N)"
            if ($confirm -match '^[Yy]') { $script:sourcesPath = ConvertTo-SourcesPath $resolved; if ($showImages) { Show-AvailableImages -sourcesBase $script:sourcesPath }; Wait-Script; return } else { Wait-Script; return }
        }
        '2' {
            Write-Host "Scanning drives..." -ForegroundColor Cyan
            # We'll collect two arrays during the scan:
            # - $candidates : paths that passed our validation checks (good to use)
            # - $rejections : diagnostic info for paths that had setup.exe or sources but failed validation (helps troubleshooting)
            $candidates = @(); $rejections = @()
            Get-PSDrive -PSProvider FileSystem | ForEach-Object {
                $root = $_.Root
                $setupFile = Join-Path $root 'setup.exe'; $sourcesDir = Join-Path $root 'sources'
                if (Test-Path $setupFile -PathType Leaf) {
                    if (Test-SetupExeValid -file $setupFile) { $candidates += $root }
                    else {
                        try { $sig = Get-AuthenticodeSignature -FilePath $setupFile -ErrorAction Stop } catch { $sig = $null }
                        try { $desc = (Get-Item $setupFile -ErrorAction Stop).VersionInfo.FileDescription } catch { $desc = $null }
                        $rejections += [pscustomobject]@{ Path = $root; Type = 'setup.exe'; Sig = ($sig.Status -or '<none>'); Signer = ($sig.SignerCertificate.Subject -or '<none>'); Desc = ($desc -or '<none>') }
                    }
                }
                elseif (Test-Path $sourcesDir -PathType Container) {
                    if (Test-SourcesValid -dir $sourcesDir) { $candidates += $root }
                    else {
                        $found = Get-ChildItem -Path $sourcesDir -File -Include 'install.wim', 'install.esd' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name -ErrorAction SilentlyContinue
                        $rejections += [pscustomobject]@{ Path = $root; Type = 'sources'; Files = (($found -join ', ') -or '<none>') }
                    }
                }
            }
            $candidates = $candidates | Sort-Object -Unique
            # If no validated candidates were discovered, show diagnostics (rejections) so the user understands why locations were skipped.
            if ($candidates.Count -eq 0) {
                Write-Host "No validated sources found." -ForegroundColor Yellow
                if ($rejections.Count -gt 0) {
                    Write-Host "Rejected locations:" -ForegroundColor Yellow
                    foreach ($r in $rejections) {
                        # Each $r contains small diagnostic fields such as Path, Type, Sig (signature status) or Files (what was found)
                        Write-Host "$($r.Path) - $($r.Type) - $([string](($r.Sig -or $r.Files -or '')) )"
                    }
                    # Explain the next step to the user: they may run the script on the target Windows machine (if running remotely) or
                    # they can re-run the scan after attaching the media; in some cases they may choose to force a rejected location.
                    Write-Host "Tip: if you trust a rejected location, you can run the tool again and manually set that path." -ForegroundColor Cyan
                }
                Wait-Script; return
            }
            Write-Host "Found sources:" -ForegroundColor Cyan
            $i = 0; foreach ($c in $candidates) { $i++; Write-Host "$i) $c" }
            $sel = Read-Host -Prompt "Enter the number to use (or 'c' to cancel)"
            if ($sel -match '^[cC]$') { return }
            if ($sel -match '^\d+$' -and [int]$sel -ge 1 -and [int]$sel -le $candidates.Count) {
                $chosen = $candidates[[int]$sel - 1]
                $script:sourcesPath = ConvertTo-SourcesPath $chosen
                Write-Host "sourcesPath set to: $($script:sourcesPath)" -ForegroundColor Green
                if ($showImages) { Show-AvailableImages -sourcesBase $script:sourcesPath }
                Wait-Script; return
            }
            Write-Host "Invalid selection." -ForegroundColor Yellow; Wait-Script; return
        }
        '3' {
            Start-UUPDumpISOBuilder
            # If the converter produced an ISO, attempt to mount it and set sourcesPath to the mounted drive
            if ($script:LastCreatedISO) {
                try {
                    Write-Host "Mounting ISO: $($script:LastCreatedISO)" -ForegroundColor Cyan
                    # Mount the ISO and attempt to discover the assigned drive letter
                    Mount-DiskImage -ImagePath $script:LastCreatedISO -ErrorAction Stop | Out-Null
                    Start-Sleep -Seconds 1
                    $vol = (Get-DiskImage -ImagePath $script:LastCreatedISO -ErrorAction SilentlyContinue | Get-Disk | Get-Partition | Get-Volume | Where-Object { $_.DriveLetter }) | Select-Object -First 1
                    if ($vol -and $vol.DriveLetter) {
                        $letter = $vol.DriveLetter
                        $script:sourcesPath = ($letter + ':\')
                        Write-Host "ISO mounted as drive $letter. sourcesPath set to $($script:sourcesPath)" -ForegroundColor Green
                        if ($showImages) { Show-AvailableImages -sourcesBase $script:sourcesPath }
                        Wait-Script; return
                    }
                    else {
                        Write-Host "Mounted ISO but could not determine the drive letter. Please mount manually and set the path." -ForegroundColor Yellow
                        Wait-Script; return
                    }
                }
                catch {
                    Write-Host "Failed to mount ISO $($script:LastCreatedISO): $_" -ForegroundColor Red
                    Write-Host "Please mount the ISO manually and then set the path using option 1." -ForegroundColor Yellow
                    Wait-Script; return
                }
            }
            else {
                Write-Host "No ISO created to mount. Aborting option 3." -ForegroundColor Yellow
                Wait-Script; return
            }
        }
        default { Write-Host "Invalid option." -ForegroundColor Yellow; Wait-Script; return }
    }
}

# ---------------------------
# Reusable Menu System
# ---------------------------
<#
.SYNOPSIS
Displays a formatted menu and returns the user's selection.

.DESCRIPTION
This is a generic, reusable menu function that displays a title, a list of options, and
prompts the user for a selection. The function handles validation and returns the selected
option key. This function is the core of the new SConfig-like interface.

.PARAMETER Title
The menu title displayed at the top.

.PARAMETER Options
A hashtable where keys are option identifiers (e.g., '1', 'a', 's') and values are option descriptions.
Example: @{'1'='Option One'; '2'='Option Two'; 'q'='Quit'}

.PARAMETER AllowedOptions
An array of allowed option keys. If omitted, derived from Options keys.

.PARAMETER Prompt
The text to display when asking for user input. Defaults to a sensible message.

.OUTPUTS
The user's selected option key as a string (e.g., '1' or 'q').

.EXAMPLE
$opts = @{
    '1' = 'First choice'
    '2' = 'Second choice'
    'q' = 'Quit'
}
$choice = Show-MenuPrompt -Title "Main Menu" -Options $opts
#>
function Show-MenuPrompt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [hashtable]$Options,

        [string[]]$AllowedOptions,

        [string]$Prompt = 'Select an option'
    )

    # If AllowedOptions is not provided, derive from the Options keys
    if (-not $AllowedOptions -or $AllowedOptions.Count -eq 0) {
        $AllowedOptions = @($Options.Keys | Sort-Object)
    }

    while ($true) {
        Clear-Host
        # Only display the title if it is not empty
        if (-not [string]::IsNullOrWhiteSpace($Title)) {
            Write-Host $Title -ForegroundColor Cyan
            Write-Host ''
        }

        # Display each option on its own line
        foreach ($key in $AllowedOptions) {
            if ($Options.ContainsKey($key)) {
                Write-Host "$key) $($Options[$key])"
            }
        }

        Write-Host ''
        $selection = Read-Host -Prompt $Prompt

        # Validate: the selection must be a key in AllowedOptions
        if ($AllowedOptions -contains $selection) {
            return $selection
        }

        # Invalid selection; show error and loop to prompt again
        Write-Host "Invalid selection. Please try again." -ForegroundColor Red
        Start-Sleep -Milliseconds 500
    }
}

# ---------------------------
# Menu Flow: Source Selection
# ---------------------------
<#
.SYNOPSIS
Main menu: prompts the user to select an installation source.

.DESCRIPTION
This is the first-level menu (SConfig-style). It offers four options:
1. Enter a path manually
2. Scan drives to find media
3. Build a new ISO installation media, mount it, and use it
4. Exit

After a source is selected and validated, the user proceeds to image/edition selection.
#>
function Show-MainSourceMenu {
    $menuOptions = @{
        '1' = 'Enter a path manually'
        '2' = 'Scan drives to find media'
        '3' = 'Build a new ISO installation media, mount it and use it'
        '0' = 'Exit'
    }

    while ($true) {
        $choice = Show-MenuPrompt -Title 'Select the installation source' -Options $menuOptions -AllowedOptions @('1', '2', '3', '0')

        switch ($choice) {
            '0' {
                Clear-Host
                Write-Host 'Exiting.' -ForegroundColor Cyan
                Exit 0
            }
            '1' {
                Set-SourcesPathInteractive '1' $false
                if ([string]::IsNullOrWhiteSpace($script:sourcesPath)) {
                    Write-Host 'Sources not set.' -ForegroundColor Yellow
                    Wait-Script
                    continue
                }
                return
            }
            '2' {
                Set-SourcesPathInteractive '2' $false
                if ([string]::IsNullOrWhiteSpace($script:sourcesPath)) {
                    Write-Host 'Sources not set.' -ForegroundColor Yellow
                    Wait-Script
                    continue
                }
                return
            }
            '3' {
                Set-SourcesPathInteractive '3' $false
                if ([string]::IsNullOrWhiteSpace($script:sourcesPath)) {
                    Write-Host 'Sources not set.' -ForegroundColor Yellow
                    Wait-Script
                    continue
                }
                return
            }
            default {
                Write-Host 'Unexpected error in menu selection.' -ForegroundColor Red
                Wait-Script
            }
        }
    }
}

# ---------------------------
# Menu Flow: Image Selection
# ---------------------------
<#
.SYNOPSIS
Displays available images and allows the user to select one.

.DESCRIPTION
This function retrieves the list of available images from the sources directory,
presents them to the user for selection, and attempts to auto-detect the corresponding edition.
If auto-detection fails, the user is prompted to select from the editions table manually.

After a successful selection, the function populates script-scoped globals:
- $script:selectedImageIndex
- $script:selectedImageFile
- $script:selectedImageName
- $script:productkey
- $script:editionid
- $script:productname
- $script:compositioneditionid
#>
function Show-ImageSelectionMenu {
    if (-not (SelectImageAndAutoSetEdition -sourcesBase $script:sourcesPath)) {
        Write-Host 'Image and edition selection failed. Returning to source menu.' -ForegroundColor Yellow
        Wait-Script
        return $false
    }
    return $true
}

# ---------------------------
# Menu Flow: Installation Method (Main)
# ---------------------------
<#
.SYNOPSIS
Main installation method menu after image/edition have been selected.

.DESCRIPTION
Displays the installation methods and utilities submenu. Options include:
- Start setup (standard): launch setup.exe with default settings
- Start setup (pre-install key): pass the pre-installation product key
- Forced upgrade: modify registry before launching setup (dangerous)
- Utilities: sub-menu with adprep and key management options
- Back: return to source selection menu

This menu loops until the user exits or returns to the source menu.
#>
function Show-InstallationMethodMenu {
    while ($true) {
        $menuOptions = @{
            '1' = 'Start setup (standard): launch setup.exe and let it choose the image/edition automatically'
            '2' = 'Start setup (pre-install key): run setup.exe and pass the pre-installation product key and the image edition selected'
            '3' = 'Forced upgrade: write EditionID/ProductName into HKLM before launching setup (dangerous, advanced)'
            '4' = 'Utilities'
            '0' = 'Back'
        }

        Clear-Host
        Write-Host 'Installation Setup' -ForegroundColor Cyan
        Write-Host "Sources: $($script:sourcesPath)" -ForegroundColor Green
        Write-Host "Selected edition: $($script:productname)" -ForegroundColor Green
        Write-Host ''

        $choice = Show-MenuPrompt -Title '' -Options $menuOptions -AllowedOptions @('1', '2', '3', '4', '0')

        switch ($choice) {
            '1' {
                Start-BoringUpgrade
                # Note: Start-BoringUpgrade calls Exit internally
            }
            '2' {
                Start-Upgrade
                # Note: Start-Upgrade calls Exit internally
            }
            '3' {
                Start-ForcedUpgrade
                # Note: Start-ForcedUpgrade calls Exit internally
            }
            '4' {
                Show-UtilitiesMenu
                # After utilities menu exits, loop back to this menu
                continue
            }
            '0' {
                # Return to source selection menu
                return
            }
            default {
                Write-Host 'Unexpected error in menu selection.' -ForegroundColor Red
                Wait-Script
            }
        }
    }
}

# ---------------------------
# Menu Flow: Utilities Submenu
# ---------------------------
<#
.SYNOPSIS
Utilities submenu for advanced operations.

.DESCRIPTION
This submenu offers:
- Set-ProductKey: change the product key on the running system using slmgr
- Run adprep /forestprep: execute the forest preparation utility from the sources
- Run adprep /domainprep: execute the domain preparation utility from the sources
- Back: return to the installation method menu

These utilities are provided for administrative workflows and should be used with caution.
#>
function Show-UtilitiesMenu {
    while ($true) {
        $menuOptions = @{
            '1' = 'Set-ProductKey: change the product key on the running system using slmgr'
            '2' = 'Run adprep /forestprep: execute the forest preparation utility from the sources'
            '3' = 'Run adprep /domainprep: execute the domain preparation utility from the sources'
            '0' = 'Back'
        }

        Clear-Host
        Write-Host 'Utilities' -ForegroundColor Cyan
        Write-Host "Sources: $($script:sourcesPath)" -ForegroundColor Green
        Write-Host ''

        $choice = Show-MenuPrompt -Title '' -Options $menuOptions -AllowedOptions @('1', '2', '3', '0')

        switch ($choice) {
            '1' {
                Set-ProductKey
                continue
            }
            '2' {
                Start-ADPrepForestPrep -sourcesBase $script:sourcesPath
                continue
            }
            '3' {
                Start-ADPrepDomainPrep -sourcesBase $script:sourcesPath
                continue
            }
            '0' {
                # Return to the installation method menu
                return
            }
            default {
                Write-Host 'Unexpected error in menu selection.' -ForegroundColor Red
                Wait-Script
            }
        }
    }
}

# ---------------------------
# Main Application Flow
# ---------------------------
<#
.SYNOPSIS
Entry point for the interactive guided upgrade workflow.

.DESCRIPTION
This function implements the top-level flow of the application. It orchestrates:
1. Source selection (Show-MainSourceMenu)
2. Image and edition selection (Show-ImageSelectionMenu)
3. Installation method choice (Show-InstallationMethodMenu)

The flow loops so the user can select a new source and start over without restarting the script.
#>
function Start-InteractiveWorkflow {
    while ($true) {
        # Step 1: Source selection
        Show-MainSourceMenu
        # sourcesPath is now set

        # Step 2: Image and edition selection
        if (-not (Show-ImageSelectionMenu)) {
            # If image selection failed, return to source menu
            continue
        }

        # Step 3: Installation method and utilities
        Show-InstallationMethodMenu
        # After returning from installation menu, loop to source selection
    }
}

# Start the main interactive workflow
Start-InteractiveWorkflow
