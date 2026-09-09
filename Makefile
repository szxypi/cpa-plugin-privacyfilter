PLUGIN_NAME ?= privacyfilter
VERSION ?= 0.3.0
BUILD_DIR ?= .
DIST_DIR ?= dist
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
GO_LDFLAGS ?= -s -w -X main.pluginVersion=$(VERSION)

EXT_linux = so
EXT_freebsd = so
EXT_darwin = dylib
EXT_windows = dll
PLUGIN_EXT = $(or $(EXT_$(GOOS)),so)
PLUGIN_OUTPUT ?= $(BUILD_DIR)/$(PLUGIN_NAME).$(PLUGIN_EXT)
PLUGIN_HEADER = $(basename $(PLUGIN_OUTPUT)).h
# CPA derives a plugin's id from its file name, so the deployable artifact is
# named <id>-v<version>.<ext>.
DIST_OUTPUT = $(DIST_DIR)/$(PLUGIN_NAME)-v$(VERSION).$(PLUGIN_EXT)
DIST_HEADER = $(basename $(DIST_OUTPUT)).h
GITLEAKS_RULES_URL ?= https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml

.PHONY: build dist test bench clean update-rules

build:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -buildmode=c-shared -ldflags "$(GO_LDFLAGS)" -o $(PLUGIN_OUTPUT) .
	rm -f $(PLUGIN_HEADER)

# dist builds the artifact ops/deploy installs, plus its checksum.
dist:
	mkdir -p $(DIST_DIR)
	CGO_ENABLED=1 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -buildmode=c-shared -ldflags "$(GO_LDFLAGS)" -o $(DIST_OUTPUT) .
	rm -f $(DIST_HEADER)
	cd $(DIST_DIR) && sha256sum $(notdir $(DIST_OUTPUT)) > $(notdir $(DIST_OUTPUT)).sha256
	@echo "built $(DIST_OUTPUT)"

test:
	go vet ./...
	go test ./...

bench:
	go test -run XXX -bench . -benchtime 10x ./...

clean:
	rm -f $(BUILD_DIR)/$(PLUGIN_NAME).so
	rm -f $(BUILD_DIR)/$(PLUGIN_NAME).dylib
	rm -f $(BUILD_DIR)/$(PLUGIN_NAME).dll
	rm -f $(PLUGIN_HEADER)
	rm -rf $(DIST_DIR)

update-rules:
	curl -fsSL $(GITLEAKS_RULES_URL) -o rules/gitleaks.toml
