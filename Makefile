include .env
export ZONEMASTER_VERSION ZONEMASTER_ENGINE_VERSION

SRC = rst-test-specs
ZM_DIR=zonemaster/zonemaster-$(ZONEMASTER_VERSION)

yaml: export ZM_VERSION=$(ZONEMASTER_VERSION)

all: zonemaster-profile rdapct-config includes yaml lint json html

.PHONY: bootstrap-internal-checker-schemas bootstrap-quality-gate quality-gate quality-gate-python quality-gate-preflight dashboard test-all

PYTHON ?= python3

# --- Perl local-lib auto-bootstrap (Info-2) ---------------------------------
# `tools/bootstrap-quality-gate.sh` installs Perl modules under $HOME/perl5
# via `cpanm --local-lib-contained`. Auto-export PERL5LIB/PATH so subsequent
# `make quality-gate` invocations find those modules without manual env
# tweaks (local devs were hitting "Can't locate Data/Mirror.pm" before this).
# CI is unaffected because the workflow already exports the same paths into
# $GITHUB_ENV before invoking make.
PERL_LOCAL_LIB := $(HOME)/perl5/lib/perl5
PERL_LOCAL_BIN := $(HOME)/perl5/bin
LOCAL_BIN      := $(HOME)/.local/bin

ifneq ($(wildcard $(PERL_LOCAL_LIB)),)
export PERL5LIB := $(PERL_LOCAL_LIB)$(if $(PERL5LIB),:$(PERL5LIB),)
endif
export PATH := $(LOCAL_BIN):$(PERL_LOCAL_BIN):$(PATH)

zonemaster-profile:
	@echo Generating Zonemaster profile...
	@tools/generate-zonemaster-profile.pl "--version=$(ZONEMASTER_ENGINE_VERSION)" > rst.json
	@echo wrote rst.json

rdapct-config:
	@echo Generating RDAP Conformance Tool configuration files...

	@tools/generate-rdapct-config.pl RSP > rdapct_config.json
	@echo wrote rdapct_config.json

	@tools/generate-rdapct-config.pl RSP > rdapct_config_rsp.json
	@echo wrote rdapct_config_rsp.json

includes:
	@rm -rf tmp
	@mkdir tmp

	@echo Generating version number and last-updated...
	@tools/generate-version.sh > tmp/version.txt
	@echo -n "Version: "
	@cat tmp/version.txt

	@tools/generate-last-updated.sh > tmp/last-updated.txt

	@echo Downloading Zonemaster source code...
	@tools/install-zonemaster "$(ZONEMASTER_VERSION)"

	@echo Generating Zonemaster cases...
	@tools/generate-zonemaster-cases.pl "--version=$(ZONEMASTER_VERSION)" "$(ZM_DIR)" > tmp/zonemaster-cases.yaml

	@echo Generating Zonemaster errors...
	@tools/generate-zonemaster-cases.pl "--version=$(ZONEMASTER_VERSION)" --errors "$(ZM_DIR)" > tmp/zonemaster-errors.yaml

	@echo Generating data providers...
	@find tools -maxdepth 1 -type f -iname '*.pl' -print
	@tools/generate-data-providers.pl ./data > tmp/data-providers.yaml

yaml:
	@echo Compiling YAML...
	@gpp -DZONEMASTER_VERSION=$(ZONEMASTER_VERSION) -DZONEMASTER_ENGINE_VERSION=$(ZONEMASTER_ENGINE_VERSION) -x $(SRC).yaml.in > $(SRC).yaml
	@echo wrote $(SRC).yaml

lint:
	@echo Checking YAML...
	@PATH="$(HOME)/.local/bin:$(PATH)" perl tools/lint.pl $(SRC).yaml
	@perl tools/lint-epp-extensions-list.pl

bootstrap-internal-checker-schemas:
	@python3 tools/bootstrap_internal_checker_schemas.py

bootstrap-quality-gate:
	@ZONEMASTER_ENGINE_VERSION="$(ZONEMASTER_ENGINE_VERSION)" tools/bootstrap-quality-gate.sh

quality-gate-python:
	@echo Running Python compliance test gate...
	@pytest -q tests

# Preflight check (Info-2): fail fast with an actionable message when the
# Perl side of the gate is not bootstrapped, instead of crashing inside
# `tools/generate-zonemaster-cases.pl` with "Can't locate Data/Mirror.pm".
quality-gate-preflight:
	@if ! perl -MICANN::RST::Spec -MData::Mirror -MZonemaster::Engine -e 1 >/dev/null 2>&1; then \
		echo ""; \
		echo "ERROR: Perl prerequisites for 'make quality-gate' are missing."; \
		echo ""; \
		echo "  Required modules (any of these may be absent):"; \
		echo "    ICANN::RST::Spec, Data::Mirror, Zonemaster::Engine,"; \
		echo "    Zonemaster::LDNS, JSON::Schema, Array::Utils,"; \
		echo "    Spreadsheet::XLSX, LWP::Protocol::https,"; \
		echo "    DateTime::Format::ISO8601"; \
		echo ""; \
		echo "  Fix options:"; \
		echo "    1) Install everything once:  make bootstrap-quality-gate"; \
		echo "    2) Run the Python-only gate: make quality-gate-python"; \
		echo "    3) Run the combined Python sweep: make test-all"; \
		echo ""; \
		echo "  Bootstrap installs modules under \$$HOME/perl5; the Makefile"; \
		echo "  auto-exports PERL5LIB so they are picked up on later runs."; \
		echo ""; \
		exit 2; \
	fi

quality-gate: quality-gate-preflight includes yaml lint quality-gate-python
	@echo "Quality gate passed (lint + python tests)"

dashboard:
	@echo "Generating internal RST dashboard (dry-run)..."
	@PYTHONPATH=src $(PYTHON) internal-rst-checker/rst_dashboard.py \
		--dry-run --reports-dir internal-rst-checker/reports
	@echo "Wrote internal-rst-checker/reports/{report.json,dashboard.html}"

test-all:
	@echo "Running combined Python test sweep (both roots)..."
	@PYTHONPATH=src $(PYTHON) -m pytest internal-rst-checker/tests tests

json:
	@echo Compiling JSON...
	@perl -MYAML::XS -MJSON::XS -e 'print JSON::XS->new->utf8->canonical->pretty->encode(YAML::XS::LoadFile("./$(SRC).yaml"))' > $(SRC).json
	@echo wrote $(SRC).json

html:
	@echo Compiling HTML...
	@perl tools/generate-html.pl $(SRC).yaml > $(SRC).html
	@echo wrote $(SRC).html

pages: rdapct-config zonemaster-profile
	@echo Generating pages...
	@tools/build-pages

clean:
	@echo Cleaning up...
	@rm -rf tmp zonemaster _site tmp rst.json rst-test-specs.html rst-test-specs.json rst-test-specs.yaml rdapct_config*.json releases.md releases.json
