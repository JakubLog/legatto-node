# Test image of the console tests: the Ubuntu 24.04 runtime of the office
# server (Python 3.12 standard library) plus what the tests need around it:
# PyYAML to read contract/contract.yml, Jinja2 and systemd to render and
# `systemd-analyze verify` unit templates (vendor deployments reuse this image
# for their unit tests), util-linux for setpriv (drop to legatto-console).
FROM ubuntu:24.04@sha256:9c7f200c07e3d4a03e7249d2c16bf66a51120fb876aa2242cf31451412543289

ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1 LANG=C.UTF-8
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-yaml python3-jinja2 systemd tzdata util-linux \
    && rm -rf /var/lib/apt/lists/*
