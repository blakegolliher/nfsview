SHELL := /usr/bin/env bash

BIN ?= nfsview
PROFILE ?= release
# `ebpf` is on by default so packaged builds carry the eBPF latency enricher.
# Override with `make FEATURES=crossterm ...` (or any other set) to opt out.
# Building with `ebpf` requires clang + libelf + zlib headers at build time and
# Linux 5.14+ with BTF (and CAP_BPF or root) at runtime.
FEATURES ?= crossterm ebpf
OUTDIR ?= dist

# Make sure cargo-installed binaries are findable even when `make` is invoked
# from a shell that didn't source ~/.cargo/env.
export PATH := $(HOME)/.cargo/bin:$(PATH)

# Detect the host package manager once so the setup helpers below can install
# missing build dependencies without a second probe per call.
PKG_MGR := $(shell \
    if   command -v apt-get >/dev/null 2>&1; then echo apt; \
    elif command -v dnf     >/dev/null 2>&1; then echo dnf; \
    elif command -v yum     >/dev/null 2>&1; then echo yum; \
    elif command -v zypper  >/dev/null 2>&1; then echo zypper; \
    elif command -v pacman  >/dev/null 2>&1; then echo pacman; \
    else echo unknown; fi)

# Drop `sudo` when already root or when sudo is unavailable. Lets the same
# recipes work in containers (typically root, no sudo) and on workstations.
SUDO := $(shell if [ "$$(id -u)" -eq 0 ] || ! command -v sudo >/dev/null 2>&1; then echo ""; else echo sudo; fi)

HOST_TARGET := $(shell rustc -vV | sed -n 's/^host: //p')
HOST_OS := $(word 3,$(subst -, ,$(HOST_TARGET)))

# Default to a single host-native build. Cross-arch builds are still possible
# by passing TARGET=<triple> (or overriding TARGETS), but the user must supply
# a matching C toolchain plus libelf/zlib for that arch — `cross` (cargo-cross)
# is the easiest path. We dropped the static-musl pipeline because libbpf-sys
# bundles libbpf C sources that need libelf and zlib headers + libraries built
# for the target libc, which musl distros don't ship.
TARGETS ?= $(HOST_TARGET)

ifeq ($(PROFILE),release)
PROFILE_FLAG := --release
else
PROFILE_FLAG :=
endif

COMMON_FLAGS := --no-default-features --features "$(FEATURES)"
PORTABLE_RUSTFLAGS := -C strip=symbols -C debuginfo=0 -C panic=abort

define ensure_target
	@if command -v rustup >/dev/null 2>&1; then \
		rustup target add $(1); \
	else \
		if [[ ! -d "$$(rustc --print sysroot)/lib/rustlib/$(1)/lib" ]]; then \
			echo "target $(1) is not installed and rustup is unavailable"; \
			echo "install rustup or use a toolchain that already has $(1) stdlib"; \
			exit 2; \
		fi; \
		echo "rustup not found; target $(1) appears installed"; \
	fi
endef

# Install $(1) via the host package manager if it is not already on PATH.
# Args: (1) command to check, (2) dnf/yum/zypper pkg, (3) apt pkg, (4) pacman pkg.
define ensure_tool
	@if ! command -v $(1) >/dev/null 2>&1; then \
		echo ">> installing $(1) via $(PKG_MGR)"; \
		case "$(PKG_MGR)" in \
			apt)            $(SUDO) apt-get update -qq && $(SUDO) apt-get install -y $(3) ;; \
			dnf|yum|zypper) $(SUDO) $(PKG_MGR) install -y $(2) ;; \
			pacman)         $(SUDO) pacman -S --noconfirm $(4) ;; \
			*) echo "** unknown package manager; please install '$(1)' manually then re-run"; exit 2 ;; \
		esac; \
		command -v $(1) >/dev/null 2>&1 || { echo "** $(1) still missing after install attempt"; exit 2; }; \
	fi
endef

.PHONY: help
help:
	@echo "make setup                  Install build deps (clang, libelf-devel, zlib-devel, pkg-config)"
	@echo "make portable-host          Build host-arch Linux binary"
	@echo "make portable-all           Build binaries for $(TARGETS)"
	@echo "make portable TARGET=<triple> Build one target (cross-arch needs a matching C toolchain)"
	@echo "make deb                    Build a .deb for the host arch (set DEB_TARGET=<triple> to cross)"
	@echo "make deb-all                Build .debs for all $(TARGETS)"
	@echo "make rpm                    Build an .rpm for the host arch (set RPM_TARGET=<triple> to cross)"
	@echo "make rpm-all                Build .rpms for all $(TARGETS)"
	@echo "make clean-dist             Remove dist/ artifacts"
	@echo
	@echo "Variables:"
	@echo "  FEATURES=$(FEATURES)"
	@echo "  PROFILE=$(PROFILE)"
	@echo "  OUTDIR=$(OUTDIR)"
	@echo "  PKG_NAME=$(PKG_NAME)  PKG_VERSION=$(PKG_VERSION)"
	@echo "  PKG_MAINTAINER=$(PKG_MAINTAINER)"
	@echo "  PKG_LICENSE=$(PKG_LICENSE)  RPM_RELEASE=$(RPM_RELEASE)"

# ---- Build dependency setup -------------------------------------------------
# `make setup` installs everything needed for the build/packaging targets:
#   - clang     (libbpf-cargo invokes it to compile BPF objects when `ebpf` is
#               in FEATURES; harmless to install when it is not)
#   - libelf + zlib headers and pkg-config (libbpf-sys's bundled libbpf C
#               sources #include <libelf.h> and <zlib.h>, and locate them via
#               pkg-config)
# Each step is idempotent — it checks first and skips if already present, so
# wiring it as a prerequisite of the build targets is cheap on re-runs.
.PHONY: setup
setup: setup-rustup setup-clang setup-bpf-deps
	@echo ">> build deps OK"

.PHONY: setup-clang
setup-clang:
	$(call ensure_tool,clang,clang,clang,clang)

.PHONY: setup-rustup
setup-rustup:
	@if ! command -v cargo >/dev/null 2>&1; then \
		echo "** cargo not installed"; \
		echo "   install rustup: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"; \
		exit 2; \
	fi

# libbpf-sys requires libelf + zlib headers/libs at build time and pkg-config
# to find them. Header presence is a more reliable check than `command -v`.
.PHONY: setup-bpf-deps
setup-bpf-deps:
	$(call ensure_tool,pkg-config,pkgconf-pkg-config,pkg-config,pkgconf)
	@if [[ ! -e /usr/include/libelf.h ]] && [[ ! -e /usr/include/elfutils/libelf.h ]]; then \
		echo ">> installing libelf headers via $(PKG_MGR)"; \
		case "$(PKG_MGR)" in \
			apt)            $(SUDO) apt-get update -qq && $(SUDO) apt-get install -y libelf-dev ;; \
			dnf|yum|zypper) $(SUDO) $(PKG_MGR) install -y elfutils-libelf-devel ;; \
			pacman)         $(SUDO) pacman -S --noconfirm libelf ;; \
			*) echo "** unknown package manager; install libelf headers manually"; exit 2 ;; \
		esac; \
	fi
	@if [[ ! -e /usr/include/zlib.h ]]; then \
		echo ">> installing zlib headers via $(PKG_MGR)"; \
		case "$(PKG_MGR)" in \
			apt)            $(SUDO) apt-get update -qq && $(SUDO) apt-get install -y zlib1g-dev ;; \
			dnf|yum|zypper) $(SUDO) $(PKG_MGR) install -y zlib-devel ;; \
			pacman)         $(SUDO) pacman -S --noconfirm zlib ;; \
			*) echo "** unknown package manager; install zlib headers manually"; exit 2 ;; \
		esac; \
	fi

.PHONY: setup-deb
setup-deb: setup
	$(call ensure_tool,ar,binutils,binutils,binutils)

.PHONY: setup-rpm
setup-rpm: setup
	$(call ensure_tool,rpmbuild,rpm-build,rpm,rpm)

# ---- Portable (musl) builds -------------------------------------------------

.PHONY: portable-host
portable-host:
	@if [[ "$(HOST_OS)" != "linux" ]]; then echo "portable-host is Linux-only"; exit 2; fi
	@$(MAKE) portable TARGET=$(HOST_TARGET) PROFILE=$(PROFILE) FEATURES="$(FEATURES)" OUTDIR="$(OUTDIR)"

.PHONY: portable
portable: setup
	@if [[ -z "$(TARGET)" ]]; then echo "Usage: make portable TARGET=<triple>"; exit 2; fi
	$(call ensure_target,$(TARGET))
	@RUSTFLAGS="$(PORTABLE_RUSTFLAGS)" cargo build $(PROFILE_FLAG) $(COMMON_FLAGS) --target $(TARGET)
	@mkdir -p $(OUTDIR)
	@cp target/$(TARGET)/$(PROFILE)/$(BIN) $(OUTDIR)/$(BIN)-$(TARGET)
	@echo "Built $(OUTDIR)/$(BIN)-$(TARGET)"
	@file $(OUTDIR)/$(BIN)-$(TARGET) || true

.PHONY: portable-all
portable-all:
	@for t in $(TARGETS); do \
		$(MAKE) portable TARGET=$$t PROFILE=$(PROFILE) FEATURES="$(FEATURES)" OUTDIR="$(OUTDIR)" || exit $$?; \
	done
	@echo "All portable artifacts are in $(OUTDIR)/"

.PHONY: clean-dist
clean-dist:
	@rm -rf $(OUTDIR)

# ---- Debian packaging --------------------------------------------------------
# Produces a .deb for installation on Debian/Ubuntu. Uses `dpkg-deb --build`
# when available, otherwise falls back to a pure `ar`+`tar` assembly so the
# package can be built on non-Debian hosts (e.g. RHEL/Rocky).

PKG_NAME        ?= $(BIN)
PKG_VERSION     ?= $(shell awk -F'"' '/^version[[:space:]]*=/ {print $$2; exit}' Cargo.toml)
PKG_MAINTAINER  ?= Blake Golliher <blakegolliher@gmail.com>
PKG_DESCRIPTION ?= Ratatui-inspired Linux NFS client monitor
PKG_HOMEPAGE    ?= https://github.com/blakegolliher/nfsview
PKG_SECTION     ?= admin
PKG_PRIORITY    ?= optional

DEB_TARGET ?= $(HOST_TARGET)

# Map Rust target triple -> Debian architecture.
ifneq (,$(findstring x86_64,$(DEB_TARGET)))
DEB_ARCH := amd64
else ifneq (,$(findstring aarch64,$(DEB_TARGET)))
DEB_ARCH := arm64
else ifneq (,$(findstring armv7,$(DEB_TARGET)))
DEB_ARCH := armhf
else
DEB_ARCH := unknown
endif

DEB_STAGE := $(OUTDIR)/deb/$(PKG_NAME)_$(PKG_VERSION)_$(DEB_ARCH)
DEB_FILE  := $(OUTDIR)/$(PKG_NAME)_$(PKG_VERSION)_$(DEB_ARCH).deb

.PHONY: deb
deb: setup-deb
	@if [[ "$(DEB_ARCH)" == "unknown" ]]; then \
		echo "DEB_TARGET=$(DEB_TARGET) does not map to a Debian arch (amd64|arm64|armhf)"; exit 2; \
	fi
	@$(MAKE) portable TARGET=$(DEB_TARGET) PROFILE=$(PROFILE) FEATURES="$(FEATURES)" OUTDIR="$(OUTDIR)"
	@rm -rf $(DEB_STAGE)
	@mkdir -p $(DEB_STAGE)/DEBIAN $(DEB_STAGE)/usr/bin $(DEB_STAGE)/usr/share/doc/$(PKG_NAME)
	@install -m 0755 $(OUTDIR)/$(BIN)-$(DEB_TARGET) $(DEB_STAGE)/usr/bin/$(BIN)
	@if [[ -f README.md ]]; then install -m 0644 README.md $(DEB_STAGE)/usr/share/doc/$(PKG_NAME)/README; fi
	@INSTALLED_SIZE=$$(du -sk --apparent-size $(DEB_STAGE)/usr | cut -f1); \
	 { \
	   echo "Package: $(PKG_NAME)"; \
	   echo "Version: $(PKG_VERSION)"; \
	   echo "Section: $(PKG_SECTION)"; \
	   echo "Priority: $(PKG_PRIORITY)"; \
	   echo "Architecture: $(DEB_ARCH)"; \
	   echo "Maintainer: $(PKG_MAINTAINER)"; \
	   echo "Installed-Size: $$INSTALLED_SIZE"; \
	   echo "Depends: libc6, libelf1, zlib1g, libzstd1"; \
	   echo "Homepage: $(PKG_HOMEPAGE)"; \
	   echo "Description: $(PKG_DESCRIPTION)"; \
	   echo " Linux NFS client monitor that reads /proc/self/mountstats,"; \
	   echo " /proc/net/rpc/nfs, and /proc/net/tcp{,6} and renders a live"; \
	   echo " ratatui dashboard of per-mount throughput, ops, and latency."; \
	 } > $(DEB_STAGE)/DEBIAN/control
	@if command -v dpkg-deb >/dev/null 2>&1; then \
	   dpkg-deb --build --root-owner-group $(DEB_STAGE) $(DEB_FILE); \
	 else \
	   command -v ar >/dev/null || { echo "need 'ar' (binutils) or dpkg-deb to build a .deb"; exit 2; }; \
	   tmp=$$(mktemp -d); trap "rm -rf $$tmp" EXIT; \
	   printf '2.0\n' > $$tmp/debian-binary; \
	   ( cd $(DEB_STAGE)/DEBIAN && tar --owner=0 --group=0 --format=gnu -czf $$tmp/control.tar.gz . ); \
	   ( cd $(DEB_STAGE) && tar --owner=0 --group=0 --format=gnu --exclude=./DEBIAN -czf $$tmp/data.tar.gz . ); \
	   ( cd $$tmp && ar rc $(abspath $(DEB_FILE)) debian-binary control.tar.gz data.tar.gz ); \
	 fi
	@echo "Built $(DEB_FILE)"
	@ls -lh $(DEB_FILE)

.PHONY: deb-all
deb-all:
	@for t in $(TARGETS); do \
		$(MAKE) deb DEB_TARGET=$$t PROFILE=$(PROFILE) FEATURES="$(FEATURES)" OUTDIR="$(OUTDIR)" || exit $$?; \
	done
	@echo "All .deb artifacts are in $(OUTDIR)/"

.PHONY: deb-clean
deb-clean:
	@rm -rf $(OUTDIR)/deb $(OUTDIR)/*.deb

# ---- RPM packaging -----------------------------------------------------------
# Produces a .rpm for installation on RHEL/Rocky/Fedora/SUSE. Uses `rpmbuild`
# directly with a generated spec file so no extra cargo tooling is required.
# Mirrors the .deb pipeline: build a host-arch glibc-dynamic binary, stage
# into a BUILDROOT, then package. The binary links to libelf/zlib/glibc at
# runtime, declared as Requires.

PKG_LICENSE ?= MIT
RPM_RELEASE ?= 1
RPM_TARGET  ?= $(HOST_TARGET)

# Map Rust target triple -> RPM architecture.
ifneq (,$(findstring x86_64,$(RPM_TARGET)))
RPM_ARCH := x86_64
else ifneq (,$(findstring aarch64,$(RPM_TARGET)))
RPM_ARCH := aarch64
else ifneq (,$(findstring armv7,$(RPM_TARGET)))
RPM_ARCH := armv7hl
else
RPM_ARCH := unknown
endif

RPM_FILE := $(OUTDIR)/$(PKG_NAME)-$(PKG_VERSION)-$(RPM_RELEASE).$(RPM_ARCH).rpm

.PHONY: rpm
rpm: setup-rpm
	@command -v rpmbuild >/dev/null || { echo "rpmbuild not found (install rpm-build)"; exit 2; }
	@if [[ "$(RPM_ARCH)" == "unknown" ]]; then \
		echo "RPM_TARGET=$(RPM_TARGET) does not map to an RPM arch (x86_64|aarch64|armv7hl)"; exit 2; \
	fi
	@$(MAKE) portable TARGET=$(RPM_TARGET) PROFILE=$(PROFILE) FEATURES="$(FEATURES)" OUTDIR="$(OUTDIR)"
	@mkdir -p $(OUTDIR)
	@tmp=$$(mktemp -d); trap "rm -rf $$tmp" EXIT; \
	  buildroot=$$tmp/buildroot; \
	  mkdir -p $$buildroot/usr/bin $$buildroot/usr/share/doc/$(PKG_NAME); \
	  install -m 0755 $(OUTDIR)/$(BIN)-$(RPM_TARGET) $$buildroot/usr/bin/$(BIN); \
	  if [[ -f README.md ]]; then install -m 0644 README.md $$buildroot/usr/share/doc/$(PKG_NAME)/README; fi; \
	  spec=$$tmp/$(PKG_NAME).spec; \
	  { \
	    echo "Name:       $(PKG_NAME)"; \
	    echo "Version:    $(PKG_VERSION)"; \
	    echo "Release:    $(RPM_RELEASE)"; \
	    echo "Summary:    $(PKG_DESCRIPTION)"; \
	    echo "License:    $(PKG_LICENSE)"; \
	    echo "URL:        $(PKG_HOMEPAGE)"; \
	    echo "Packager:   $(PKG_MAINTAINER)"; \
	    echo "BuildArch:  $(RPM_ARCH)"; \
	    echo "Requires:   glibc, elfutils-libelf, zlib"; \
	    echo "%define _build_id_links none"; \
	    echo "%define __strip /bin/true"; \
	    echo ""; \
	    echo "%description"; \
	    echo "Linux NFS client monitor that reads /proc/self/mountstats,"; \
	    echo "/proc/net/rpc/nfs, and /proc/net/tcp{,6} and renders a live"; \
	    echo "ratatui dashboard of per-mount throughput, ops, and latency."; \
	    echo ""; \
	    echo "%files"; \
	    echo "%attr(0755,root,root) /usr/bin/$(BIN)"; \
	    if [[ -f README.md ]]; then echo "%doc /usr/share/doc/$(PKG_NAME)/README"; fi; \
	  } > $$spec; \
	  mkdir -p $$tmp/rpmbuild/{BUILD,RPMS,SRPMS,SOURCES,SPECS}; \
	  rpmbuild --quiet \
	    --define "_topdir $$tmp/rpmbuild" \
	    --define "dist %{nil}" \
	    --buildroot $$buildroot \
	    --target $(RPM_ARCH) \
	    -bb $$spec; \
	  cp $$tmp/rpmbuild/RPMS/$(RPM_ARCH)/$(PKG_NAME)-$(PKG_VERSION)-$(RPM_RELEASE).$(RPM_ARCH).rpm $(RPM_FILE)
	@echo "Built $(RPM_FILE)"
	@ls -lh $(RPM_FILE)

.PHONY: rpm-all
rpm-all:
	@for t in $(TARGETS); do \
		$(MAKE) rpm RPM_TARGET=$$t PROFILE=$(PROFILE) FEATURES="$(FEATURES)" OUTDIR="$(OUTDIR)" || exit $$?; \
	done
	@echo "All .rpm artifacts are in $(OUTDIR)/"

.PHONY: rpm-clean
rpm-clean:
	@rm -f $(OUTDIR)/*.rpm
