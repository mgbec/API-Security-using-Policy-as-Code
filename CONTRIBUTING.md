# Contributing

This repo enforces the [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
via policy as code. Changes to Terraform, the OpenAPI contract, or handler
code must pass every policy gate before merge.

## Local workflow

```bash
# one-time setup
make install          # or: ./tasks.ps1 install   (elevated PowerShell on Windows)

# before pushing
make all              # or: ./tasks.ps1 all
```

`make all` runs Terraform fmt/validate, Checkov (+ custom OWASP policies),
Trivy, Spectral, Semgrep, and Conftest. Fix any findings before opening a PR.
Pre-commit hooks run the fast subset automatically on `git commit`.

## Required status checks (repo admins)

CI runs on every PR, but it only *blocks* merges once branch protection is
configured. To enable:

1. Go to **Settings → Branches → Add branch protection rule**.
2. Set **Branch name pattern** to `main`.
3. Enable **Require a pull request before merging**.
4. Enable **Require status checks to pass before merging**, then search for
   and select each job from the `policy-as-code` workflow:
   - `gitleaks (secrets)`
   - `checkov (IaC)`
   - `trivy (config)`
   - `spectral (OpenAPI)`
   - `semgrep (SAST)`
   - `conftest (OPA plan policy)`
5. (Recommended) Enable **Require branches to be up to date before merging**.
6. Save.

Status-check names appear in the dropdown only after the workflow has run at
least once, so open a throwaway PR first if the list is empty.

## Adding or changing policies

| Scope | Where | Example |
|-------|-------|---------|
| Terraform source rule | `policies/checkov/` | attribute (YAML) or logic (Python) |
| Plan-graph / cross-resource rule | `policies/opa/api_security.rego` | `deny` / `warn` rules |
| API-contract rule | `.spectral.yaml` | OWASP ruleset overrides |

Map each new rule to a specific OWASP API risk in a comment, and update the
coverage table in `README.md` so the mapping stays accurate.

## Suppressions

Suppress a Checkov finding inline only with a justification:

```hcl
# checkov:skip=CKV_OWASP_API2_1: public health-check route, no PII, rate-limited
```

Unjustified or broad suppressions will be rejected in review.
