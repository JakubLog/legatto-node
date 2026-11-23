# Test runner for tests/egress: Ubuntu 24.04 with the host packages that
# legatto-egress uses on the server (python3 3.12, nftables, iproute2).
FROM docker.io/library/ubuntu:24.04@sha256:9c7f200c07e3d4a03e7249d2c16bf66a51120fb876aa2242cf31451412543289
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 nftables iproute2 \
    && rm -rf /var/lib/apt/lists/*
