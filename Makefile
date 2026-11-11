SHELL := /bin/bash
.DEFAULT_GOAL := help
.DELETE_ON_ERROR:

NPM ?= npm
PYTHON ?= python3
OPEN ?= open
APP_BUNDLE := $(CURDIR)/src-tauri/target/release/bundle/macos/Cyberbot.app

.PHONY: help deps install build run dev web-dev web-build web-preview \
        test test-ui test-collector test-collector-linux test-rust test-check-runner test-ssh test-ssh-pool \
        check fmt fmt-check icons test-install test-notifications test-actions version-check bump-version clean

help: ## Show available commands
	@awk 'BEGIN {FS = ":.*## "; print "Cyberbot development commands\n"} /^[a-z][a-z-]*:.*## / {printf "  make %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

deps: ## Install Node dependencies from package-lock.json
	$(NPM) ci

install: ## Build and install Cyberbot in Applications
	bash scripts/install-macos.sh check
	$(MAKE) deps
	$(MAKE) build
	bash scripts/install-macos.sh install "$(APP_BUNDLE)"

icons: ## Rebuild application icons from the radar artwork
	$(NPM) run icons

build: ## Build the macOS app (Cyberbot.app)
	$(NPM) run desktop:build

run: build ## Build and open the macOS app
	$(OPEN) "$(APP_BUNDLE)"

dev: ## Run the desktop app in development mode
	$(NPM) run desktop

web-dev: ## Start the browser preview with fictional data
	$(NPM) run dev

web-build: ## Type-check and build the frontend
	$(NPM) run build

web-preview: web-build ## Build and serve the frontend preview
	$(NPM) run preview -- --host 127.0.0.1

test: test-ui test-collector test-rust test-check-runner test-install ## Run the local tests without a model or Docker

test-ui: ## Run Vue tests with Vitest
	$(NPM) test

test-collector: ## Run Python collector tests
	$(NPM) run test:collector

test-collector-linux: ## Run collector tests in a Linux Docker container
	docker build --build-arg EXTRA_PACKAGES=nginx -t cyberbot-collector-test:local tests/integration
	docker run --rm --network none -w /work --entrypoint python3 \
		-v "$(CURDIR)/collectors:/work/collectors:ro" -v "$(CURDIR)/tests:/work/tests:ro" \
		cyberbot-collector-test:local -B -m unittest discover -s tests -p 'test_*.py'

test-rust: ## Build check-runner and test the Rust app
	$(NPM) run test:rust

test-check-runner: ## Test the isolated check runner
	bash scripts/cargo.sh test --manifest-path check-runner/Cargo.toml

test-install: ## Test macOS installation with temporary app bundles
	$(PYTHON) scripts/test-install-macos.py

test-notifications: ## Test native macOS notifications with a separate signed app
	/usr/bin/python3 scripts/test-notifications-macos.py --hold

test-ssh: ## Test SSH and rsync against a disposable Docker fixture
	$(PYTHON) scripts/test-ssh.py

test-ssh-pool: ## Test SSH pooling on macOS with Docker
	/usr/bin/python3 scripts/test-ssh-pool.py --isolation

test-actions: ## Test isolation, Nginx, read and shell approvals without a model (Docker)
	$(PYTHON) scripts/test-ai-actions.py --wait-seconds 12
	$(PYTHON) scripts/test-ai-actions.py --no-build --shell
	docker run --rm --network none -v "$(CURDIR):/work:ro" -w /work --entrypoint python3 cyberbot-actions-test:local -B -m unittest discover -s /work/tests -p test_actions.py
	docker run --rm --network none -v "$(CURDIR):/work:ro" -w /work --entrypoint python3 cyberbot-actions-test:local -B -m unittest discover -s /work/tests -p test_remote_read.py

version-check: ## Validate all release version fields and notes
	$(PYTHON) scripts/version.py check

bump-version: ## Bump the app version with BUMP=patch, minor, or major
	$(PYTHON) scripts/version.py bump "$(BUMP)"

check: version-check web-build test fmt-check ## Run local checks before committing

fmt: ## Format Rust code for the app and check-runner
	bash scripts/cargo.sh fmt --manifest-path src-tauri/Cargo.toml
	bash scripts/cargo.sh fmt --manifest-path check-runner/Cargo.toml

fmt-check: ## Check Rust formatting
	bash scripts/cargo.sh fmt --manifest-path src-tauri/Cargo.toml -- --check
	bash scripts/cargo.sh fmt --manifest-path check-runner/Cargo.toml -- --check

clean: ## Remove build output while preserving dependencies and app data
	rm -rf dist src-tauri/target src-tauri/binaries check-runner/target
