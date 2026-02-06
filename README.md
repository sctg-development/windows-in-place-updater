# windows-in-place-updater ✅

A small interactive PowerShell helper to perform in-place upgrades of Windows installations outside the standard Microsoft update channel.

## What it does 🔧

- Guides the user through selecting or providing Windows installation media (ISO or `sources\`).
- Can create a custom ISO from UUP Dump (download UUP files and convert them to an ISO) using UUP Dump + UUP Converter.
- Lets you select an image within the media and perform an in-place upgrade (standard or with a pre-installed product key).
- Includes safety checks (signature verification for setup.exe, SHA256 checks for downloaded helper tools).

## Important notes ⚠️

> **This script does NOT activate Windows.** You must already have a valid license for the **target edition** you install. Using this tool without a proper license may violate Microsoft's terms.

- The script requires Administrator privileges (it will relaunch itself elevated when needed).
- A reliable internet connection and about 10 GiB free space are recommended when creating ISOs from UUP Dump.
- The script attempts to verify downloaded helper binaries (aria2c, 7zr, UUP converter) using SHA256; always inspect and verify before trusting binaries.

## Prerequisites ✔️

- Windows (client or server)
- PowerShell (run the script using an elevated PowerShell session)
- Internet access for UUP downloads (when using the ISO creation feature)

## How to use ▶️

1. Clone or download this repository.
2. Open an elevated PowerShell prompt in the repository root.
3. Run:

```powershell
.\windows-in-place-updater.ps1
```

Follow the interactive menus to choose a source, create an ISO from UUP Dump, pick an image, and start setup.

## UUP & converter links 🔗

- UUP Dump: https://git.uupdump.net/uup-dump
- UUP Converter (uup-converter-wimlib / convert-UUP.cmd): https://github.com/abbodi1406/BatUtil/tree/master/uup-converter-wimlib

The script can automatically download and verify these helper tools when needed.

## Security & Legal 📜

Use this script at your own risk. Always back up important data before performing upgrades. This repository is provided as-is; it does not bypass licensing or activation requirements.

## Developer Guide 👨‍💻

This section provides guidance for developers who want to extend or modify the script.

### Architecture Overview

The script is organized into logical sections:

1. **Initialization & Security**: TLS setup, elevation check, global variables
2. **Helper Functions**: File operations, downloads, validation
3. **API Integration**: UUP Dump interactions, ISO building
4. **System Detection**: Architecture, Windows kind, language detection
5. **Business Logic**: Setup execution, registry manipulation, ADPrep
6. **UI System**: Reusable menu functions and interactive workflows

### Key Conventions

#### Variable Scope
- All global/state variables use the `script:` scope
- Use `$script:varName` consistently across functions
- Document new global variables in the "Global variables" section

#### Naming Conventions
- **Functions**: Use Verb-Noun pattern (PowerShell standard)
  - `Get-*` for retrieval operations
  - `Set-*` for assignment/configuration
  - `Test-*` for validation/checking
  - `Install-*` for setup/installation
  - `Start-*` for workflow/execution
  - `Show-*` for UI display

#### Documentation Standards
All functions must include a PSDoc block:

```powershell
<#
.SYNOPSIS
One-line description of what it does.

.DESCRIPTION
Detailed explanation of behavior, parameters, and interactions.
Include warnings if applicable.

.PARAMETER ParamName
Description of parameter (repeat for each parameter).

.OUTPUTS
Description of return value or output.

.NOTES
Additional context, warnings, or implementation notes.
#>
function My-Function {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RequiredParam,
        
        [string]$OptionalParam = 'default'
    )
    
    # Implementation
}
```

#### Error Handling
- Use `try/catch` for external operations (network, file I/O)
- Provide user-friendly error messages with context
- Use `Wait-Script` to pause before returning from error states
- Log to console with appropriate colors (Red for error, Yellow for warning, Green for success, Cyan for info)

### Creating New Menu Items

The menu system uses a reusable `Show-MenuPrompt` function. To add a new menu:

```powershell
function Show-MyCustomMenu {
    <#
    .SYNOPSIS
    Description of menu purpose.
    #>
    
    while ($true) {
        $menuOptions = @{
            '1' = 'Option one description'
            '2' = 'Option two description'
            '0' = 'Back'
        }

        Clear-Host
        Write-Host 'Custom Menu Title' -ForegroundColor Cyan
        Write-Host "Current state: $($script:sourcesPath)" -ForegroundColor Green
        Write-Host ''

        $choice = Show-MenuPrompt -Title '' -Options $menuOptions -AllowedOptions @('1', '2', '0')

        switch ($choice) {
            '1' {
                # Call action for option 1
                Do-Action
                continue
            }
            '2' {
                # Call action for option 2
                Do-Action2
                continue
            }
            '0' {
                # Return to parent menu
                return
            }
        }
    }
}
```

Then integrate it into `Show-InstallationMethodMenu`:

```powershell
# In Show-InstallationMethodMenu, add to $menuOptions:
'5' = 'My Custom Menu'

# In the switch statement:
'5' {
    Show-MyCustomMenu
    continue
}
```

### Adding New Functions

Follow this template for new business logic functions:

```powershell
<#
.SYNOPSIS
Do something useful.

.DESCRIPTION
Explain what it does, what it requires, and what it affects.

.PARAMETER Path
Full description of the path parameter.

.OUTPUTS
What does it return?

.NOTES
Any warnings or special requirements.
#>
function Do-CustomTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    # Validate inputs
    if (-not (Test-Path $Path)) {
        Write-Host "Path not found: $Path" -ForegroundColor Red
        Wait-Script
        return $false
    }

    # Perform operation
    try {
        # Your code here
        Write-Host "Task completed successfully." -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "Error during task: $_" -ForegroundColor Red
        Wait-Script
        return $false
    }
}
```

### Integrating New Operations into Workflows

To add a new operation to the installation workflow:

1. Create the operation function with appropriate documentation
2. Call it from the relevant menu function
3. Handle return values and display status

Example:

```powershell
# In Show-InstallationMethodMenu
'6' {
    if (Invoke-CustomPreflightChecks) {
        Write-Host "Preconditions met. Proceeding..." -ForegroundColor Green
        Wait-Script
    }
    continue
}
```

### Working with Script State

Access the global state variables carefully:

```powershell
# Read current source path
$currentSource = $script:sourcesPath

# Update edition information
$script:productkey = 'XXXXX-XXXXX-XXXXX-XXXXX-XXXXX'
$script:editionid = 'Professional'
$script:productname = 'Windows 11 Pro'

# Check selected image
if ($null -eq $script:selectedImageIndex) {
    Write-Host "No image selected yet." -ForegroundColor Yellow
}
```

### Adding New Dependencies

When adding new downloaded tools:

1. Define variables for file info:
```powershell
$script:myToolFile = 'mytool.exe'
$script:myToolUrl = 'https://example.com/mytool.exe'
$script:myToolHash = 'sha256hashhere'
```

2. Create an install function:
```powershell
function Install-MyTool {
    if ((Test-FileExistence -File $script:myToolFile) -and (Test-Hash -File $script:myToolFile -Hash $script:myToolHash)) {
        Write-Host "MyTool is ready." -ForegroundColor Green
        return $true
    }

    if (-not (Test-Path -PathType Container -Path "files")) {
        $null = New-Item -Path "files" -ItemType Directory
    }

    $ProgressPreference = 'SilentlyContinue'
    try {
        Get-RemoteFile -File $script:myToolFile -Url $script:myToolUrl
    }
    catch {
        Write-Host "Failed to download $($script:myToolFile)"
        return $false
    }

    if (-not (Test-Hash -File $script:myToolFile -Hash $script:myToolHash)) {
        Write-Error "$($script:myToolFile) appears to be tampered with"
        return $false
    }
    return $true
}
```

3. Call it before using the tool:
```powershell
if (-not (Install-MyTool)) {
    Write-Host "MyTool is required but unavailable." -ForegroundColor Red
    Wait-Script
    return
}
```

### Testing Your Changes

1. **Syntax validation**: The script includes inline comments documenting syntax rules
2. **Manual testing**: Always test on a non-production system
3. **Error paths**: Test both success and failure scenarios
4. **User input validation**: Ensure all user inputs are validated
5. **Menu flow**: Verify navigation between menus works correctly

Example test:
```powershell
# Load the script without running it
. .\windows-in-place-updater.ps1 -NoClean

# Test a specific function
Test-SetupExeValid -file "C:\path\to\setup.exe"
```

### Common Patterns

#### Prompting for User Confirmation

```powershell
$confirm = Read-Host -Prompt "Continue? (y/N)"
if ($confirm -notmatch '^[Yy]') {
    Write-Host "Cancelled." -ForegroundColor Yellow
    return
}
```

#### Validating Paths

```powershell
try {
    $resolved = Resolve-Path -LiteralPath $userInput -ErrorAction Stop
    $path = $resolved.ProviderPath
}
catch {
    Write-Host "Invalid path: $userInput" -ForegroundColor Red
    Wait-Script
    return
}
```

#### Checking Prerequisites

```powershell
if (-not (Test-FileExistence -File $script:aria2cFile)) {
    if (-not (Install-Aria2c)) {
        Write-Host "aria2c is required but could not be installed." -ForegroundColor Red
        Wait-Script
        return
    }
}
```

### Performance Considerations

- Network operations: Use `$ProgressPreference = 'SilentlyContinue'` to reduce console overhead
- Large file transfers: Use aria2c for parallel downloads
- WMI queries: Cache results when querying the same information multiple times
- Nested loops: Avoid deep nesting; consider extracting to separate functions

### Deployment & Distribution

When distributing your modified script:

1. Update the version number in the header comment
2. Test thoroughly on target Windows versions
3. Include SHA256 hashes for any new helper tools
4. Document new features and breaking changes in the README
5. Keep the MIT License intact

## License

This project is released under the MIT License. See `LICENSE.md` for details.
