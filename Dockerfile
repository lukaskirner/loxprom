# Build a static binary first:  cargo build --release --target <arch>-unknown-linux-musl
# Then:  docker build --build-arg BIN=target/<arch>-unknown-linux-musl/release/loxprom -t loxprom .
# CI places binaries at dist/<amd64|arm64>/loxprom and builds multi-arch via TARGETARCH.
FROM scratch
ARG TARGETARCH
ARG BIN=dist/${TARGETARCH}/loxprom
COPY --chmod=0755 ${BIN} /loxprom
EXPOSE 9876
ENTRYPOINT ["/loxprom"]
