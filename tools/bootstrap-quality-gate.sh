#!/usr/bin/env bash
set -euo pipefail

echo "Bootstrapping dependencies for quality gate..."

install_pkg() {
  local apt_pkg="$1"
  local brew_pkg="$2"
  local apk_pkg="$3"

  if command -v apt-get >/dev/null 2>&1; then
    if [ "$(id -u)" -eq 0 ]; then
      apt-get update
      apt-get install -y "$apt_pkg"
    elif command -v sudo >/dev/null 2>&1; then
      sudo apt-get update
      sudo apt-get install -y "$apt_pkg"
    else
      return 1
    fi
    return 0
  fi

  if command -v brew >/dev/null 2>&1; then
    brew install "$brew_pkg"
    return 0
  fi

  if command -v apk >/dev/null 2>&1; then
    apk add --no-cache "$apk_pkg"
    return 0
  fi

  return 1
}

check_zonemaster_engine_version() {
  perl -Mversion -MZonemaster::Engine -e '
    exit(
      version->parse($Zonemaster::Engine::VERSION) <=>
      version->parse($ENV{ZONEMASTER_ENGINE_VERSION})
    )
  ' >/dev/null 2>&1
}

if ! command -v perl >/dev/null 2>&1; then
  echo "error: perl is required"
  exit 1
fi

if ! command -v cpanm >/dev/null 2>&1; then
  echo "cpanm not found. Attempting automatic install..."
  install_pkg cpanminus cpanminus perl-app-cpanminus || {
    echo "error: failed to install cpanm automatically"
    exit 1
  }
fi

if ! command -v dot >/dev/null 2>&1; then
  echo "graphviz (dot) not found. Attempting automatic install..."
  install_pkg graphviz graphviz graphviz || {
    echo "error: failed to install graphviz automatically"
    exit 1
  }
fi

if [ -z "${ZONEMASTER_ENGINE_VERSION:-}" ]; then
  echo "error: ZONEMASTER_ENGINE_VERSION environment variable must be set"
  exit 1
fi

need_perl_modules=0

if ! perl -MICANN::RST::Spec -e 1 >/dev/null 2>&1; then
  need_perl_modules=1
fi

if ! check_zonemaster_engine_version; then
  need_perl_modules=1
fi

if [ "${need_perl_modules}" -eq 1 ]; then
  echo "Installing Perl modules for lint and Zonemaster generation..."
  cpanm --quiet --notest --local-lib-contained "${HOME}/perl5" \
    ICANN::RST JSON::Schema Array::Utils Data::Mirror \
    Zonemaster::LDNS "Zonemaster::Engine@${ZONEMASTER_ENGINE_VERSION}"
else
  echo "Perl lint and Zonemaster modules already installed"
fi

if ! command -v go >/dev/null 2>&1; then
  echo "go not found. Attempting automatic install..."
  install_pkg golang-go go go || {
    echo "error: failed to install go automatically"
    exit 1
  }
fi

mkdir -p "${HOME}/.local/bin"

if ! PATH="${HOME}/.local/bin:${PATH}" command -v schemalint >/dev/null 2>&1; then
  echo "Installing schemalint..."
  GOBIN="${HOME}/.local/bin" go install github.com/giantswarm/schemalint/v2@latest
else
  echo "schemalint already installed"
fi

echo "Bootstrap complete. Ensure PATH includes: ${HOME}/.local/bin"
echo "Perl modules installed under: ${HOME}/perl5"
