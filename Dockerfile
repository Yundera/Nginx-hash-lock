# AppShield 3.0 — single static binary, no shell, no package manager, no nginx.
#
# Replaces the 2.x image (nginx:latest + NodeSource Node 22, 589 MB) with a
# ~11 MB scratch image. Dockerfile.v2 still builds the 2.x nginx+Node image and
# is kept until 3.0 has proven itself in staging, so a rollback stays buildable.

# --platform=$BUILDPLATFORM keeps the toolchain native and lets Go cross-compile
# for the target. The alternative — emulating an arm64 Go compile under QEMU —
# is slow and prone to spurious failures.
FROM --platform=$BUILDPLATFORM golang:1.25 AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src

# Dependencies first so a source-only change does not re-resolve modules.
COPY go.mod go.sum* ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
COPY web ./web

ARG VERSION=3.0.0-dev
# -s -w drop the symbol table and DWARF; the binary is not debugged in place.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /appshield ./cmd/appshield

# Confirm the binary really is static. Reading the embedded build settings works
# for a cross-compiled binary, where ldd on the build host would not.
RUN go version -m /appshield | grep -q 'CGO_ENABLED=0' \
    || (echo "binary was built with cgo; it would fail on scratch" && exit 1)

# scratch has no filesystem, and the unprivileged user cannot create top-level
# directories at runtime. Stage them here so a deployment that mounts nothing
# still has somewhere to write.
RUN mkdir -p /stage/data /stage/tmp && chmod 700 /stage/data /stage/tmp

FROM scratch

# CA roots for outbound TLS to the OIDC registrar and provider.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
# The Go resolver reads these; without nsswitch.conf it can skip /etc/hosts.
COPY --from=build /etc/nsswitch.conf /etc/nsswitch.conf

COPY --from=build --chown=65534:65534 /stage/data /data
COPY --from=build --chown=65534:65534 /stage/tmp /tmp

COPY --from=build /appshield /appshield

# Unprivileged. The 2.x image ran nginx as root to bind port 80; container
# networking makes that unnecessary since the port is namespaced.
USER 65534:65534

EXPOSE 80
ENTRYPOINT ["/appshield"]
