# Build a fully static binary, then ship it in an empty, non-root image.
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
# Cache dependencies separately from the source.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && touch src/lib.rs \
    && cargo build --release --locked && rm -rf src
COPY src ./src
RUN touch src/main.rs src/lib.rs && cargo build --release --locked

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /src/target/release/kubesieve /usr/local/bin/kubesieve
USER nonroot
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/kubesieve"]
CMD ["--help"]
