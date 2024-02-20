# Get started with a build env with Rust nightly
FROM rustlang/rust:nightly-alpine as builder

RUN apk update && \
    apk add --no-cache bash curl npm libc-dev binaryen

RUN npm install -g sass

RUN curl --proto '=https' --tlsv1.2 -LsSf https://github.com/leptos-rs/cargo-leptos/releases/latest/download/cargo-leptos-installer.sh | sh

# Add the WASM target
RUN rustup target add wasm32-unknown-unknown

WORKDIR /work
COPY Cargo.lock Cargo.toml rust-toolchain.toml .
COPY src src
COPY style style

RUN mkdir -p public && cargo leptos build --release -vv

FROM scratch as runner

WORKDIR /app

COPY --from=builder /work/target/release/cyclone /app/
COPY --from=builder /work/target/site /app/site
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 3000
ENV LEPTOS_SITE_ROOT=/app/site
ENV LEPTOS_SITE_ADDR=0.0.0.0:3000

CMD ["/app/cyclone"]
