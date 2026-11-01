# Build first:  cargo build --release --target <arch>-unknown-linux-musl
# Then:         docker build --build-arg BIN=target/<arch>-unknown-linux-musl/release/loxprom -t loxprom .
FROM scratch
ARG BIN=target/release/loxprom
COPY ${BIN} /loxprom
EXPOSE 9876
ENTRYPOINT ["/loxprom"]
