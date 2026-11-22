# Egress proxy image (Smokescreen) for the per-role container proxies
# egress-<role> (PLAN D9, contract legatto_egress_container_proxies).
# Owner: egress lane. Built by release/build.sh:
#   docker buildx build --platform linux/amd64 egress/image
#
# Supply chain:
#   - Smokescreen is built from source at a pinned commit (the commit of tag
#     v0.1.0, same release as the host binary in versions.yml), checked after
#     checkout; dependencies come from the repository's vendor/ directory
#     (-mod=vendor), so the build fetches nothing but the pinned commit;
#   - both base images are pinned by digest (versions.yml: legatto_images.
#     golang_build.index_digest and legatto_images.distroless_static.digest);
#     tests/egress checks that these values match versions.yml.
#
# Runtime: distroless static, uid 65532, no shell. The container reads
# /etc/smokescreen/smokescreen.yaml and /etc/smokescreen/acl.yaml from a
# read-only bind mount of /etc/legatto/egress/proxy/<role> (legatto-egress).

ARG SMOKESCREEN_REPO=https://github.com/stripe/smokescreen.git
ARG SMOKESCREEN_COMMIT=609eb8931420453daf5893509be0b25b21bd9edb

FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.25.14-trixie@sha256:2c4c60ef415fbfa5e90300722293bef36c5e63fae17570ce18f580af933dbd73 AS build
ARG SMOKESCREEN_REPO
ARG SMOKESCREEN_COMMIT
ARG TARGETOS
ARG TARGETARCH
ENV CGO_ENABLED=0 \
    GOFLAGS=-mod=vendor \
    GOTOOLCHAIN=local \
    GOPROXY=off \
    GOSUMDB=off
WORKDIR /src
RUN git init -q . \
    && git remote add origin "${SMOKESCREEN_REPO}" \
    && git fetch -q --depth 1 origin "${SMOKESCREEN_COMMIT}" \
    && git checkout -q --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "${SMOKESCREEN_COMMIT}" \
    && test -z "$(git status --porcelain)"
RUN GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build -trimpath -buildvcs=false \
        -ldflags="-s -w -buildid=" -o /out/smokescreen . \
    && GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build -trimpath -buildvcs=false \
        -ldflags="-s -w -buildid=" -o /out/smokescreen-check-config ./cmd/check_config

FROM gcr.io/distroless/static-debian13:nonroot@sha256:816dc4d589459a7fe33b8a2e69edb70da56ffad7161f4b415937fa2bfe7e92e8
ARG SMOKESCREEN_COMMIT
LABEL org.opencontainers.image.title="legatto-egress-proxy" \
      org.opencontainers.image.description="Smokescreen egress proxy for one container role" \
      org.opencontainers.image.source="https://github.com/stripe/smokescreen" \
      org.opencontainers.image.revision="${SMOKESCREEN_COMMIT}" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /out/smokescreen /out/smokescreen-check-config /usr/local/bin/
USER 65532:65532
EXPOSE 4750
ENTRYPOINT ["/usr/local/bin/smokescreen"]
CMD ["--config-file", "/etc/smokescreen/smokescreen.yaml"]
