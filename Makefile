# Makefile — Naija Scam Shield Build & Dev Shortcuts
# Author: Joshua Akadri | GitHub: sudopenmark
# Usage: make <target>

PYTHON  := python3
PIP     := pip3
APP     := main.py
DIST    := dist
SPEC    := naija_scam_shield.spec
APP_NAME := NaijaScamShield

# ── Development ───────────────────────────────────────────────────────────────

.PHONY: run
run:                        ## Launch the desktop app
	$(PYTHON) $(APP)

.PHONY: install
install:                    ## Install all Python dependencies
	$(PIP) install -r requirements.txt

.PHONY: install-dev
install-dev: install        ## Install dev + test dependencies
	$(PIP) install pytest pytest-cov pyinstaller briefcase

.PHONY: test
test:                       ## Run all unit tests
	$(PYTHON) -m pytest tests/ -v

.PHONY: test-coverage
test-coverage:              ## Run tests with coverage report
	$(PYTHON) -m pytest tests/ -v --cov=. --cov-report=term-missing --cov-report=html
	@echo "Coverage report: htmlcov/index.html"

.PHONY: test-offline
test-offline:               ## Run only offline/unit tests (no network)
	$(PYTHON) -m pytest tests/ -v -m "not network"

.PHONY: lint
lint:                       ## Run flake8 linter
	$(PYTHON) -m flake8 core/ ui/ database/ reports/ tests/ \
	    --max-line-length=120 --ignore=E501,W503

.PHONY: format
format:                     ## Auto-format with black
	$(PYTHON) -m black core/ ui/ database/ reports/ tests/ main.py --line-length=100

.PHONY: typecheck
typecheck:                  ## Run mypy type checks
	$(PYTHON) -m mypy core/ database/ reports/ --ignore-missing-imports

# ── Signature updates ─────────────────────────────────────────────────────────

.PHONY: update-sigs
update-sigs:                ## Pull latest scam domain signatures
	$(PYTHON) scripts/update_signatures.py

# ── Windows EXE (run on Windows or Wine) ─────────────────────────────────────

.PHONY: build-windows
build-windows:              ## Build Windows EXE with PyInstaller
	$(PIP) install pyinstaller
	pyinstaller $(SPEC) --clean --noconfirm
	@echo "✅ Windows EXE: $(DIST)/$(APP_NAME).exe"

# ── Linux Binary ──────────────────────────────────────────────────────────────

.PHONY: build-linux
build-linux:                ## Build Linux binary with PyInstaller
	$(PIP) install pyinstaller
	pyinstaller $(SPEC) --clean --noconfirm
	@echo "✅ Linux binary: $(DIST)/$(APP_NAME)"

.PHONY: build-linux-appimage
build-linux-appimage:       ## Build Linux AppImage (requires appimage-builder)
	@which appimage-builder || (echo "Install appimage-builder: pip install appimage-builder" && exit 1)
	make build-linux
	appimage-builder --recipe AppImageBuilder.yml
	@echo "✅ Linux AppImage created"

# ── Android APK (via BeeWare Briefcase) ──────────────────────────────────────

.PHONY: build-android
build-android:              ## Build Android APK with Briefcase + Kivy
	$(PIP) install briefcase
	briefcase create android
	briefcase build android
	@echo "✅ Android APK: android/gradle/app/build/outputs/apk/"

.PHONY: run-android
run-android:                ## Run Android app in emulator
	briefcase run android

.PHONY: run-mobile
run-mobile:                 ## Run Kivy mobile UI on desktop (preview)
	$(PYTHON) ui/mobile_app.py

# ── All platform builds ───────────────────────────────────────────────────────

.PHONY: build-all
build-all:                  ## Build all desktop targets
	make build-linux
	@echo "Run 'make build-windows' on Windows, 'make build-android' for APK."

# ── Cleanup ───────────────────────────────────────────────────────────────────

.PHONY: clean
clean:                      ## Remove build artifacts
	rm -rf build/ dist/ *.egg-info __pycache__
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	@echo "✅ Cleaned build artifacts"

.PHONY: clean-all
clean-all: clean            ## Remove build artifacts AND test/coverage data
	rm -rf htmlcov/ .coverage .pytest_cache/ .mypy_cache/
	@echo "✅ Full clean complete"

# ── Assets ────────────────────────────────────────────────────────────────────

.PHONY: gen-assets
gen-assets:                 ## Generate placeholder icon/splash assets
	$(PYTHON) scripts/gen_assets.py
	@echo "✅ Assets generated in assets/"

# ── Help ─────────────────────────────────────────────────────────────────────

.PHONY: help
help:                       ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	    | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
