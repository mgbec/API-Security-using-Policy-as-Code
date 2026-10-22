# Policy-as-code task runner.
#
# Python tools come from requirements.txt. Node, Go, and binary tools are
# installed by the `install` target below. On Windows, run these from a
# bash shell (Git Bash or WSL) where `make` is available; the individual
# tool commands also work standalone in PowerShell (see README).

SHELL := /bin/bash
TF_DIR := terraform
API_GLOB := api/**/*.{yml,yaml,json}
SPECTRAL := npx @stoplight/spectral-cli@6.14.2
PLAN_JSON := $(TF_DIR)/tfplan.json

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
.PHONY: install
install: ## Install all policy-as-code tools (Python + Node + binaries)
	pip install -r requirements.txt
	pre-commit install
	npm i -g @stoplight/spectral-cli@6.14.2 @stoplight/spectral-owasp-ruleset@2.5.0
	@echo ""
	@echo "Install the following binaries via your package manager if missing:"
	@echo "  terraform  -> https://developer.hashicorp.com/terraform/install"
	@echo "  trivy      -> https://trivy.dev/latest/getting-started/installation/"
	@echo "  conftest   -> https://www.conftest.dev/install/"
	@echo "  gitleaks   -> https://github.com/gitleaks/gitleaks#installing"

# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------
.PHONY: all
all: fmt validate checkov trivy spectral semgrep conftest ## Run every check

.PHONY: precommit
precommit: ## Run all pre-commit hooks across the repo
	pre-commit run --all-files

# ---------------------------------------------------------------------------
# Terraform
# ---------------------------------------------------------------------------
.PHONY: fmt
fmt: ## Check Terraform formatting
	terraform -chdir=$(TF_DIR) fmt -check -recursive

.PHONY: validate
validate: ## Validate Terraform configuration
	terraform -chdir=$(TF_DIR) init -backend=false -input=false
	terraform -chdir=$(TF_DIR) validate

.PHONY: plan
plan: ## Produce the Terraform plan JSON for Conftest
	terraform -chdir=$(TF_DIR) init -backend=false -input=false
	terraform -chdir=$(TF_DIR) plan -out=tfplan.binary -input=false
	terraform -chdir=$(TF_DIR) show -json tfplan.binary > tfplan.json

# ---------------------------------------------------------------------------
# Policy / security scans (mapped to OWASP API Top 10)
# ---------------------------------------------------------------------------
.PHONY: checkov
checkov: ## IaC scan + custom OWASP policies (API2/4/5/7/8)
	checkov -d $(TF_DIR) --external-checks-dir policies/checkov --compact

.PHONY: trivy
trivy: ## Terraform config scan (API8)
	trivy config --severity HIGH,CRITICAL --exit-code 1 $(TF_DIR)

.PHONY: spectral
spectral: ## OpenAPI contract lint w/ OWASP ruleset (API1/2/3/4/5/9)
	$(SPECTRAL) lint "$(API_GLOB)" --ruleset .spectral.yaml --fail-severity warn

.PHONY: semgrep
semgrep: ## SAST on handler code (API1/3/7/10)
	semgrep scan --config auto --config p/owasp-top-ten --error src

.PHONY: conftest
conftest: plan ## OPA policy on the Terraform plan graph (API4/6/7/8/9)
	conftest test $(PLAN_JSON) --policy policies/opa --all-namespaces

.PHONY: secrets
secrets: ## Scan the repo for committed secrets (API2/8)
	gitleaks detect --source . --redact

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
.PHONY: clean
clean: ## Remove Terraform working files and plan artifacts
	rm -rf $(TF_DIR)/.terraform $(TF_DIR)/.terraform.lock.hcl
	rm -f $(TF_DIR)/tfplan.binary $(TF_DIR)/tfplan.json
