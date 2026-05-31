<#
.SYNOPSIS
Runs the Cloudflare Python automation workflow safely.

.DESCRIPTION
This script validates the project setup, prompts for required Cloudflare
environment variables, activates the local Python virtual environment,
installs requests if needed, runs cloudflare_automation.py in dry-run mode,
and only runs real mode after the user explicitly types YES.
#>

$ErrorActionPreference = "Stop"

# ---------------- Configuration ----------------
$VenvActivatePath = ".\.venv\Scripts\Activate.ps1"
$AutomationScriptPath = ".\cloudflare_automation.py"
$RequiredEnvVars = @(
    "CLOUDFLARE_API_TOKEN",
    "CLOUDFLARE_ZONE_ID",
    "CLOUDFLARE_WWW_IP",
    "CLOUDFLARE_DNS_NAME"
)
# ------------------------------------------------

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-WarningMessage {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Stop-WithError {
    param(
        [string]$Message,
        [int]$ExitCode = 1
    )
    Write-Host "[ERROR] $Message" -ForegroundColor Red
    exit $ExitCode
}

function Get-MaskedValue {
    param(
        [string]$Name,
        [string]$Value
    )

    if ($Name -match "TOKEN|SECRET|KEY|PASSWORD") {
        return "********"
    }

    return $Value
}

function Read-RequiredEnvVar {
    param([string]$Name)

    $value = [Environment]::GetEnvironmentVariable($Name, "Process")

    if ([string]::IsNullOrWhiteSpace($value)) {
        $value = [Environment]::GetEnvironmentVariable($Name, "User")
    }

    if (-not [string]::IsNullOrWhiteSpace($value)) {
        $maskedValue = Get-MaskedValue -Name $Name -Value $value
        Write-WarningMessage "$Name is already set: $maskedValue"
        $replacement = Read-Host "Press Enter to keep this value, or type a new value"

        if (-not [string]::IsNullOrWhiteSpace($replacement)) {
            $value = $replacement.Trim()
        }
    }
    else {
        do {
            $value = Read-Host "Enter $Name"
            $value = $value.Trim()

            if ([string]::IsNullOrWhiteSpace($value)) {
                Write-Host "$Name is required and cannot be empty." -ForegroundColor Red
            }
        } while ([string]::IsNullOrWhiteSpace($value))
    }

    [Environment]::SetEnvironmentVariable($Name, $value, "Process")
    Set-Item -Path "Env:$Name" -Value $value
}

function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$Command,
        [Parameter(Mandatory = $true)]
        [string]$FailureMessage
    )

    & $Command
    $exitCode = $LASTEXITCODE

    if ($null -ne $exitCode -and $exitCode -ne 0) {
        Stop-WithError "$FailureMessage Exit code: $exitCode" $exitCode
    }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Cloudflare Python Automation Workflow" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# Step 1: Validate required files.
Write-Step "Checking project files"

if (-not (Test-Path -LiteralPath $VenvActivatePath)) {
    Stop-WithError "Virtual environment activation script not found: $VenvActivatePath"
}

if (-not (Test-Path -LiteralPath $AutomationScriptPath)) {
    Stop-WithError "Python automation script not found: $AutomationScriptPath"
}

Write-Success "Found virtual environment: $VenvActivatePath"
Write-Success "Found Python script: $AutomationScriptPath"

# Step 2: Prompt for required environment variables.
Write-Step "Configuring Cloudflare environment variables"

foreach ($envVarName in $RequiredEnvVars) {
    Read-RequiredEnvVar -Name $envVarName
}

foreach ($envVarName in $RequiredEnvVars) {
    $envValue = (Get-Item -Path "Env:$envVarName").Value

    if ([string]::IsNullOrWhiteSpace($envValue)) {
        Stop-WithError "$envVarName is not set."
    }

    $maskedValue = Get-MaskedValue -Name $envVarName -Value $envValue
    Write-Success "$envVarName = $maskedValue"
}

# Step 3: Activate the Python virtual environment in this session.
Write-Step "Activating Python virtual environment"

try {
    . $VenvActivatePath
}
catch {
    Stop-WithError "Failed to activate virtual environment: $($_.Exception.Message)"
}

$pythonCommand = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCommand) {
    Stop-WithError "Python was not found after activating the virtual environment."
}

Write-Success "Using Python: $($pythonCommand.Source)"
Invoke-CheckedCommand -Command { python --version } -FailureMessage "Python version check failed."

# Step 4: Install requests if it is missing.
Write-Step "Checking Python dependency: requests"

python -c "import requests" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-WarningMessage "requests is not installed. Installing requests..."
    Invoke-CheckedCommand -Command { python -m pip install requests } -FailureMessage "Failed to install requests."
}
else {
    Write-Success "requests is already installed."
}

# Step 5: Run the automation in dry-run mode first.
Write-Step "Running dry-run mode"

$env:DRY_RUN = "1"
[Environment]::SetEnvironmentVariable("DRY_RUN", "1", "Process")

Invoke-CheckedCommand -Command { python $AutomationScriptPath } -FailureMessage "Dry-run failed."
Write-Success "Dry-run completed successfully."

# Step 6: Ask for explicit confirmation before real mode.
Write-Step "Confirm real mode"

$confirmation = Read-Host "Dry-run completed. Type YES to apply changes and run real mode"

if ($confirmation -ne "YES") {
    Write-WarningMessage "Real mode was not confirmed. Exiting without applying changes."
    exit 0
}

# Step 7: Run real mode.
Write-Step "Running real mode"

$env:DRY_RUN = "0"
[Environment]::SetEnvironmentVariable("DRY_RUN", "0", "Process")

Invoke-CheckedCommand -Command { python $AutomationScriptPath } -FailureMessage "Real mode failed."

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Cloudflare automation workflow completed successfully." -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
