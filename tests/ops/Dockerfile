# Test image for tests/ops: the target userland (Ubuntu 24.04, Python 3.12)
# plus the APT tools legatto-recovery-pack uses (age, qrencode), zbarimg and
# rsvg-convert to decode the printed QR codes back, and openssl for the test
# CA of the Kuma push test. Multi-arch index digest of ubuntu:24.04.
FROM docker.io/library/ubuntu:24.04@sha256:9c7f200c07e3d4a03e7249d2c16bf66a51120fb876aa2242cf31451412543289
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      python3 python3-yaml age qrencode zbar-tools librsvg2-bin openssl \
 && rm -rf /var/lib/apt/lists/*
