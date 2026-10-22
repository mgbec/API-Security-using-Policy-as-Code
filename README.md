# OWASP API Security — Policy as Code (Terraform + GitHub)

Policy-as-code scaffolding that catches the [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
risks **before they reach a cloud account** — first at the developer's
machine via pre-commit hooks, then as an authoritative gate in GitHub Actions.

Target stack: **Terraform** (AWS) + **GitHub**.

> The OWASP references below are paraphrased for licensing compliance.

---

## What's in here

```
.
├── .pre-commit-config.yaml      # local fast-feedback hooks
├── .spectral.yaml               # OpenAPI lint ruleset (OWASP API ruleset)
├── Makefile                     # task runner (make install / make all)
├── tasks.ps1                    # Windows PowerShell task runner
├── requirements.txt             # pinned Python tools
├── .github/workflows/
│   └── policy-as-code.yml        # CI enforcement gate (PR check)
├── api/
│   └── openapi.yaml              # example OWASP-aligned API contract
├── policies/
│   ├── checkov/                  # custom Checkov checks (OWASP-mapped)
│   │   ├── api2_apigw_authorization.py
│   │   ├── api4_apigw_throttling.yaml
│   │   ├── api7_imdsv2_required.py
│   │   └── api8_apigw_waf_logging.yaml
│   └── opa/
│       └── api_security.rego     # Conftest policy on the Terraform plan
├── src/
│   └── handler.py                # example Lambda; Semgrep SAST target
└── terraform/
    ├── main.tf                   # hardened API GW + WAF + Cognito + Lambda
    └── variables.tf
```

---

## The toolchain

| Tool | Scans | Primary OWASP coverage |
|------|-------|------------------------|
| **gitleaks** | commits for secrets | API2, API8 |
| **Checkov** (+ custom policies) | Terraform source | API2, API4, API5, API7, API8 |
| **Trivy** | Terraform config (defense-in-depth) + CVEs | API8 |
| **Spectral** (OWASP ruleset) | OpenAPI contract | API1, API2, API3, API4, API5, API9 |
| **Semgrep** | handler source code | API1, API3, API7, API10 |
| **Conftest/OPA** | Terraform **plan** JSON | API4, API6, API7, API8, API9 |

Defense in depth: contract linting, IaC scanning, SAST, and plan-graph
policy each catch a different slice. A risk missed by one layer is usually
caught by another.

---

## OWASP API Top 10 (2023) → where it's caught

| Risk | Caught by |
|------|-----------|
| **API1** Broken Object Level Authorization | Spectral (per-path auth + docs), Semgrep (ownership check) |
| **API2** Broken Authentication | Checkov `CKV_OWASP_API2_1`, Spectral (security schemes), gitleaks |
| **API3** Broken Object Property Level Authorization | Spectral (`additionalProperties:false`), Semgrep (field allowlist) |
| **API4** Unrestricted Resource Consumption | Checkov `CKV_OWASP_API4_1`, Conftest (throttling), Spectral (array limits) |
| **API5** Broken Function Level Authorization | Checkov `CKV_OWASP_API2_1`, Spectral (per-operation security) |
| **API6** Unrestricted Access to Sensitive Business Flows | Conftest (WAF present warn), Terraform WAF Bot/rate rules |
| **API7** Server-Side Request Forgery | Checkov `CKV_OWASP_API7_1`, Conftest (IMDSv2), Semgrep |
| **API8** Security Misconfiguration | Checkov `CKV_OWASP_API8_1`, Trivy, Conftest (logging), gitleaks |
| **API9** Improper Inventory Management | Conftest (required tags), Spectral (info/versioning) |
| **API10** Unsafe Consumption of APIs | Semgrep (response validation) |

---

## Quick start

### 0. Install the tooling (one command)

Python tools are pinned in `requirements.txt`; a task runner installs the
rest. Use whichever fits your shell:

```bash
# macOS / Linux / Git Bash / WSL
make install
```

```powershell
# Windows PowerShell (no `make` needed)
./tasks.ps1 install
```

`install` sets up pre-commit, Checkov, Semgrep (Python) and Spectral (Node).
On Windows, `./tasks.ps1 install` also installs the binary tools (terraform,
trivy, conftest, gitleaks) via **Chocolatey** automatically — run it from an
**elevated** PowerShell so Choco can install, and existing tools are skipped.
If Chocolatey isn't present it falls back to printing install links. On
macOS/Linux, `make install` prints links for the binaries (install via your
package manager, e.g. `brew`). Once installed, run **all** checks at once:

```bash
make all           # or: ./tasks.ps1 all
```

Run a single check by name, e.g. `make checkov` / `./tasks.ps1 checkov`.
List every task with `make help` / `./tasks.ps1 help`.

### 1. Install the local hooks

```bash
pip install -r requirements.txt
pre-commit install
pre-commit run --all-files   # scan the whole repo once
```

This runs terraform fmt/validate, gitleaks, Checkov (with the custom
`policies/checkov` checks), Trivy, and Spectral on every commit. Local
hooks can be skipped with `--no-verify`, which is why CI is the real gate.

### 2. CI gate (GitHub Actions)

`.github/workflows/policy-as-code.yml` runs on every PR to `main` and
uploads SARIF to the **Security** tab so findings annotate the PR inline.
Make it blocking:

1. Push this repo to GitHub.
2. Open a PR — the `policy-as-code` jobs run automatically.
3. In **Settings → Branches → Branch protection rules** for `main`, mark the
   jobs (`checkov`, `trivy`, `spectral`, `semgrep`, `gitleaks`, `conftest`)
   as **required status checks**.

### 3. Run individual tools manually

```bash
# IaC misconfig + custom OWASP policies
checkov -d terraform --external-checks-dir policies/checkov

# OpenAPI contract lint
npx @stoplight/spectral-cli lint api/openapi.yaml --ruleset .spectral.yaml

# Policy against the resolved plan graph
terraform -chdir=terraform init -backend=false
terraform -chdir=terraform plan -out=tfplan.binary
terraform -chdir=terraform show -json tfplan.binary > terraform/tfplan.json
conftest test terraform/tfplan.json --policy policies/opa --all-namespaces

# SAST on handler code
semgrep scan --config auto --config p/owasp-top-ten src
```

---

## Example Terraform

`terraform/main.tf` is a reference HTTP API intentionally built to **pass**
all the policies here, so you can see what "green" looks like:

- **Cognito** user pool + client with short-lived tokens and MFA (API2)
- API Gateway v2 **JWT authorizer**; route uses `authorization_type = JWT`, not `NONE` (API2/API5)
- Stage with **throttling** (API4) and **access logging** (API8)
- **WAFv2** web ACL with rate-based + managed rules, associated to the stage (API6/API8)
- `owner` / `environment` **tags** on taggable resources (API9)

To see the policies *fail*, flip a value — e.g. set a route's
`authorization_type = "NONE"`, drop `default_route_settings`, or remove the
tags — and re-run Checkov/Conftest.

---

## Extending

- **New org rule, source-level:** add a YAML or Python check under
  `policies/checkov/` (see the two styles already there).
- **New org rule, plan-level / cross-resource:** add a `deny`/`warn` rule to
  `policies/opa/api_security.rego`.
- **New API-contract rule:** add to the `rules:` block in `.spectral.yaml`.

---

## Notes & caveats

- Tool/action versions are pinned in the config files; bump them deliberately
  (e.g. with Dependabot) rather than floating to `latest`.
- Pre-commit is advisory (bypassable); **branch protection + required checks**
  is the enforcement boundary.
- Policy as code catches *known, declarable* misconfigurations. It complements
  but does not replace runtime protection (WAF, API-layer authz), DAST, and
  security review — especially for logic-heavy risks like API1/API5/API6.
