<#
.SYNOPSIS
  PowerShell task runner — Windows-friendly equivalent of the Makefile.

.DESCRIPTION
  Use this when `make` is not installed (common on Windows). Mirrors the
  Makefile targets so the policy-as-code checks run with one command.

.EXAMPLE
  ./tasks.ps1 install
  ./tasks.ps1 all
  ./tasks.ps1 checkov
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('help', 'install', 'all', 'precommit', 'fmt', 'validate',
        'plan', 'checkov', 'trivy', 'spectral', 'semgrep', 'conftest',
        'secrets', 'clean')]
    [string]$Task = 'help'
)

$ErrorActionPreference = 'Stop'
$TfDir = 'terraform'
$PlanJson = "$TfDir/tfplan.json"

function Invoke-Step($name, $script) {
    Write-Host "==> $name" -ForegroundColor Cyan
    & $script
    if ($LASTEXITCODE -ne 0) { throw "$name failed (exit $LASTEXITCODE)" }
}

function Task-Help {
    Write-Host "Usage: ./tasks.ps1 <task>`n"
    Write-Host "Tasks:"
    @(
        @('install', 'Install Python + Node tools; see notes for binaries'),
        @('all', 'Run every check (fmt, validate, checkov, trivy, spectral, semgrep, conftest)'),
        @('precommit', 'Run all pre-commit hooks across the repo'),
        @('fmt', 'Check Terraform formatting'),
        @('validate', 'Validate Terraform configuration'),
        @('plan', 'Produce the Terraform plan JSON for Conftest'),
        @('checkov', 'IaC scan + custom OWASP policies (API2/4/5/7/8)'),
        @('trivy', 'Terraform config scan (API8)'),
        @('spectral', 'OpenAPI contract lint w/ OWASP ruleset (API1/2/3/4/5/9)'),
        @('semgrep', 'SAST on handler code (API1/3/7/10)'),
        @('conftest', 'OPA policy on the Terraform plan graph (API4/6/7/8/9)'),
        @('secrets', 'Scan the repo for committed secrets (API2/8)'),
        @('clean', 'Remove Terraform working files and plan artifacts')
    ) | ForEach-Object { "  {0,-12} {1}" -f $_[0], $_[1] }
}

function Install-Binaries {
    # Install the Go/binary tools via Chocolatey when available. Each is
    # installed only if missing so re-running `install` is safe (idempotent).
    $binaries = @('terraform', 'trivy', 'conftest', 'gitleaks')
    $choco = Get-Command choco -ErrorAction SilentlyContinue

    if (-not $choco) {
        Write-Host "`nChocolatey not found; skipping binary auto-install." -ForegroundColor Yellow
        Write-Host "Install Chocolatey (https://chocolatey.org/install) then re-run," -ForegroundColor Yellow
        Write-Host "or install these manually:" -ForegroundColor Yellow
        Write-Host "  terraform -> https://developer.hashicorp.com/terraform/install"
        Write-Host "  trivy     -> https://trivy.dev/latest/getting-started/installation/"
        Write-Host "  conftest  -> https://www.conftest.dev/install/"
        Write-Host "  gitleaks  -> https://github.com/gitleaks/gitleaks#installing"
        return
    }

    foreach ($b in $binaries) {
        if (Get-Command $b -ErrorAction SilentlyContinue) {
            Write-Host "  $b already installed - skipping" -ForegroundColor DarkGray
            continue
        }
        Write-Host "==> choco install $b" -ForegroundColor Cyan
        # choco needs an elevated shell; -y auto-confirms.
        choco install $b -y
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  choco install $b failed (are you in an elevated shell?)" -ForegroundColor Yellow
        }
    }
}

function Task-Install {
    Invoke-Step 'pip install' { pip install -r requirements.txt }
    Invoke-Step 'pre-commit install' { pre-commit install }
    Invoke-Step 'npm install spectral' {
        npm i -g '@stoplight/spectral-cli@6.14.2' '@stoplight/spectral-owasp-ruleset@2.5.0'
    }
    Install-Binaries
}

function Task-Fmt { Invoke-Step 'terraform fmt' { terraform -chdir=$TfDir fmt -check -recursive } }

function Task-Validate {
    Invoke-Step 'terraform init' { terraform -chdir=$TfDir init -backend=false -input=false }
    Invoke-Step 'terraform validate' { terraform -chdir=$TfDir validate }
}

function Task-Plan {
    Invoke-Step 'terraform init' { terraform -chdir=$TfDir init -backend=false -input=false }
    Invoke-Step 'terraform plan' { terraform -chdir=$TfDir plan -out=tfplan.binary -input=false }
    Invoke-Step 'terraform show -json' {
        terraform -chdir=$TfDir show -json tfplan.binary | Out-File -Encoding utf8 $PlanJson
    }
}

function Task-Checkov { Invoke-Step 'checkov' { checkov -d $TfDir --external-checks-dir policies/checkov --compact } }
function Task-Trivy { Invoke-Step 'trivy' { trivy config --severity HIGH,CRITICAL --exit-code 1 $TfDir } }
function Task-Spectral {
    Invoke-Step 'spectral' {
        npx '@stoplight/spectral-cli@6.14.2' lint 'api/**/*.{yml,yaml,json}' --ruleset .spectral.yaml --fail-severity warn
    }
}
function Task-Semgrep { Invoke-Step 'semgrep' { semgrep scan --config auto --config p/owasp-top-ten --error src } }
function Task-Conftest {
    Task-Plan
    Invoke-Step 'conftest' { conftest test $PlanJson --policy policies/opa --all-namespaces }
}
function Task-Secrets { Invoke-Step 'gitleaks' { gitleaks detect --source . --redact } }
function Task-Precommit { Invoke-Step 'pre-commit' { pre-commit run --all-files } }

function Task-All {
    Task-Fmt; Task-Validate; Task-Checkov; Task-Trivy; Task-Spectral; Task-Semgrep; Task-Conftest
    Write-Host "`nAll checks passed." -ForegroundColor Green
}

function Task-Clean {
    Remove-Item -Recurse -Force "$TfDir/.terraform", "$TfDir/.terraform.lock.hcl" -ErrorAction SilentlyContinue
    Remove-Item -Force "$TfDir/tfplan.binary", "$TfDir/tfplan.json" -ErrorAction SilentlyContinue
    Write-Host "Cleaned Terraform artifacts."
}

switch ($Task) {
    'help' { Task-Help }
    'install' { Task-Install }
    'all' { Task-All }
    'precommit' { Task-Precommit }
    'fmt' { Task-Fmt }
    'validate' { Task-Validate }
    'plan' { Task-Plan }
    'checkov' { Task-Checkov }
    'trivy' { Task-Trivy }
    'spectral' { Task-Spectral }
    'semgrep' { Task-Semgrep }
    'conftest' { Task-Conftest }
    'secrets' { Task-Secrets }
    'clean' { Task-Clean }
}
