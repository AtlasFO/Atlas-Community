# Running Atlas in Docker

`Dockerfile` builds a self-contained image on Ubuntu 24.04 — `install.sh
--yes` runs at build time, so `docker run` never needs a first-boot setup
step. `docker-compose.yml` is a ready-to-edit starting point.

```bash
cp .env.example .env      # then edit it — see docs/llm.md for backends
docker compose build
docker compose run --rm atlas guide
```

## The one thing you must not skip: loop-device access

Disk-image tools (`tsk.*`, `img.*`, `carving.*` — anything that mounts or
carves an E01/dd/VMDK image) need loop-mount access and `CAP_SYS_ADMIN`.
Docker's default container profile grants neither. `install.sh` probes for
this at build time and prints a warning if it's missing, but the fix has to
happen at `docker run`/`docker compose` time, not in the image itself —
capabilities are a property of the running container, not something an
image can grant itself.

Two ways to fix it, from simplest to narrowest:

```bash
# Simple: full privileged mode
docker run --privileged ...

# Narrower: just what loop-mounting needs
docker run --cap-add SYS_ADMIN --device /dev/loop-control ...
```

`docker-compose.yml` ships with `privileged: true` by default (commented
alternative lines show the narrower form) — this is the one setting worth
reading before you rely on the container for a real case involving disk
images. Without either, Atlas still runs fine for memory-only or
log/PCAP-only investigations; only the image-mounting tools report
themselves unavailable.

## Case evidence

Mount `~/cases`-equivalent as a volume (`docker-compose.yml` does this via
`ATLAS_CASES_DIR`, defaulting to `./cases-data`) rather than baking it into
the image or a named Docker volume — this keeps evidence on host storage
under your own control, not inside Docker's storage driver, and lets you
inspect/back it up with ordinary filesystem tools.

## Non-interactive build

`install.sh --yes` is what runs at build time — every prompt (the sudoers
confirmation doesn't apply since the build runs as root, the optional LLM
Hub key entry, the optional zeek/suricata offer) takes its default and the
build proceeds unattended. Pass extra flags via the build arg:

```bash
docker build --build-arg ATLAS_EXTRA_FLAGS="--with-network-tools" .
```

## Rebuilding after an Atlas update

The image bakes a specific checkout at build time — `docker compose build`
(or `docker build .` again) after pulling repo updates to pick them up.
There's no in-container update path; treat the image as disposable and
rebuild it, same as you'd do for any other Dockerized application.
