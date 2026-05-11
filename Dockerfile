FROM alpine:latest

RUN apk update

#
# to speed the cpanm stage up, install as many transient dependencies as apk
# packages as possible
#
RUN apk add --quiet \
    bzip2 \
    curl \
    gcc \
    git \
    graphviz \
    libidn2-dev \
    make \
    musl-dev \
    openssl-dev \
    pandoc \
    go \
    yq \
    jq \
    bash \
    perl-app-cpanminus \
    perl-autovivification \
    perl-carp-assert \
    perl-class-accessor \
    perl-clone \
    perl-cpanel-json-xs \
    perl-datetime-format-iso8601 \
    perl-dev \
    perl-devel-checklib \
    perl-exporter-tiny \
    perl-extutils-config \
    perl-extutils-depends \
    perl-extutils-helpers \
    perl-extutils-installpaths \
    perl-file-sharedir \
    perl-file-slurp \
    perl-file-which \
    perl-graph \
    perl-io-socket-inet6 \
    perl-json \
    perl-json-maybexs \
    perl-json-xs \
    perl-list-moreutils \
    perl-locale-msgfmt \
    perl-log-any \
    perl-lwp-protocol-https \
    perl-mail-spf \
    perl-mailtools \
    perl-match-simple \
    perl-module-build-tiny \
    perl-module-install \
    perl-moo \
    perl-moose \
    perl-pod-coverage \
    perl-readonly \
    perl-test-differences \
    perl-test-exception \
    perl-test-fatal \
    perl-test-nowarnings \
    perl-test-pod \
    perl-test-requires \
    perl-test-warnings \
    perl-text-csv \
    perl-text-csv_xs \
    perl-text-unidecode \
    perl-tie-ixhash \
    perl-type-tiny \
    perl-uri \
    perl-xml-libxml \
    perl-yaml \
    perl-yaml-libyaml \
    perl-spreadsheet-xlsx

#
# gpp is not available as an Alpine package; build from source.
#
RUN set -eux; \
    curl -fsSL "https://github.com/logological/gpp/releases/download/2.28/gpp-2.28.tar.bz2" | tar -xj; \
    cd gpp-2.28; \
    ./configure --quiet; \
    make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)" install; \
    cd /; \
    rm -rf /gpp-2.28; \
    command -v gpp

#
# this is a required build argument and sets the version of Zonemaster::Engine
# we want. This argument is propagated from .env in docker-compose.yml
#
ARG ZONEMASTER_ENGINE_VERSION

#
# install remaining dependencies
#
RUN cpanm --quiet --notest ICANN::RST HTML::Tiny GraphViz2 JSON::Schema Array::Utils \
    Data::Mirror Zonemaster::LDNS Zonemaster::Engine@${ZONEMASTER_ENGINE_VERSION}

RUN GOPATH=/usr/local go install github.com/giantswarm/schemalint/v2@latest
