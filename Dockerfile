# Atlas — standalone container image.
#
# Base: Ubuntu 24.04 (noble) by default — the installer's hardened primary
# target, so this build doubles as continuous verification of the no-SIFT
# install path. Override BASE_IMAGE to build against the installer's other
# hardened target instead:
#   docker build --build-arg BASE_IMAGE=debian:12 .
# (see .github/workflows/docker-compat.yml, which builds both on every PR
# that touches install.sh/install-versions.env/requirements*.txt, plus a
# weekly schedule). install.sh runs at BUILD time (not on first
# `docker run`) so the image is immediately usable.
#
# IMPORTANT — disk-image tools need loop-device access, which Docker doesn't
# grant by default. Run the container with either:
#   docker run --privileged ...
# or, more narrowly:
#   docker run --cap-add SYS_ADMIN --device /dev/loop-control ...
# See docs/docker.md for the full explanation and docker-compose.yml for a
# ready-to-edit example. Without one of these, Atlas still runs — only
# tsk.*/img.*/carving.* (anything touching a mounted disk image) will report
# itself unavailable.

ARG BASE_IMAGE=ubuntu:24.04
FROM ${BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# install.sh itself installs python3/venv/pip and every forensic tool it
# needs — the only thing the image needs before handing off to it is git
# (to clone RegRipper, and for pip to fetch INDXParse's pinned commit) and curl/ca-certificates (chainsaw/EZ Tools
# downloads, apt HTTPS repos), plus sudo since install.sh's detection expects
# either root (this image runs as root, so sudo is actually unused/shadowed —
# kept installed anyway for anyone who execs into the container as a
# non-root user later).
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
        ca-certificates curl git sudo software-properties-common \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/atlas
COPY . .

# --yes: no TTY at build time. --with-network-tools is intentionally left
# off — opt in explicitly at build time if you want it:
#   docker build --build-arg ATLAS_EXTRA_FLAGS="--with-network-tools" .
ARG ATLAS_EXTRA_FLAGS=""
RUN ./install.sh --yes ${ATLAS_EXTRA_FLAGS}

# Case evidence and the .env secrets file are runtime concerns, not build
# concerns — mount them (see docker-compose.yml). /root/cases matches
# install.sh's own ~/cases convention for a root-run container.
VOLUME ["/root/cases"]

ENTRYPOINT ["/opt/atlas/bin/atlas"]
CMD ["--help"]
