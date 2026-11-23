# Test image of the platform lane: Ubuntu 24.04 (target OS) with the stdlib Python
# 3.12 used by the host tools, openssl, systemd-analyze and iproute2. Built locally
# by tests/platform/run.sh; never pushed. Base pinned by index digest.
FROM docker.io/library/ubuntu:24.04@sha256:9c7f200c07e3d4a03e7249d2c16bf66a51120fb876aa2242cf31451412543289
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      python3 openssl ca-certificates iproute2 systemd \
 && rm -rf /var/lib/apt/lists/*
