# syntax=docker/dockerfile:1

# CloudPass in one image: the sync server and the web portal it serves.
#
# Two artifacts come out of one builder stage, because they share almost every dependency:
# the server binary, and the wasm module the browser loads. Building them in one stage means
# the shared crates (`cloudpass-core`, `cloudpass-client`, their whole dependency tree) are
# compiled once, and the registry cache is downloaded once.
#
# What this image is for: looking at the portal, and running it on a home server. It is
# **not** a hardened deployment — see docs/ROADMAP.md for what a public one still needs
# (PostgreSQL, backups, rate limiting, TLS in front).

# ---------------------------------------------------------------------------
# Stage 1: build
# ---------------------------------------------------------------------------

# `rust:1-bookworm` rather than the 1.85 in `rust-version`. The declared minimum is a
# promise about the source, and checking it is a separate, deliberate exercise; pinning the
# image to it here would mostly mean debugging dependency drift while trying to look at the
# portal. The `-bookworm` (not `-slim`) variant is the one that already has the C toolchain,
# pkg-config and git that a Rust build needs.
FROM rust:1-bookworm AS builder

# The CLI and the crate must match exactly; a mismatch is a hard error at build time rather
# than a subtle runtime bug, which is the better failure.
ARG WASM_BINDGEN_VERSION=0.2.129

# The prebuilt release, not `cargo install`. The CLI is a large dependency tree, and
# compiling it would add minutes to every cold build for a binary upstream already ships.
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
        amd64) target=x86_64-unknown-linux-musl ;; \
        arm64) target=aarch64-unknown-linux-musl ;; \
        *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    url="https://github.com/rustwasm/wasm-bindgen/releases/download/${WASM_BINDGEN_VERSION}/wasm-bindgen-${WASM_BINDGEN_VERSION}-${target}.tar.gz"; \
    curl -fsSL -o /tmp/wasm-bindgen.tar.gz "$url"; \
    tar -xzf /tmp/wasm-bindgen.tar.gz -C /tmp; \
    mv "/tmp/wasm-bindgen-${WASM_BINDGEN_VERSION}-${target}/wasm-bindgen" /usr/local/bin/; \
    rm -rf /tmp/wasm-bindgen.tar.gz "/tmp/wasm-bindgen-${WASM_BINDGEN_VERSION}-${target}"; \
    wasm-bindgen --version

WORKDIR /src
COPY . .

# The target is added **after** the copy, and the order is the whole point of these two
# lines.
#
# `rust-toolchain.toml` at the repository root pins `channel = "stable"`. Rustup resolves the
# toolchain from the *current directory*, so cargo invoked in `/src` uses `stable` — which is
# not necessarily the toolchain this image ships as its default. Adding the target before the
# copy installs it for one toolchain and builds with the other, and the failure reads
# "the `wasm32-unknown-unknown` target may not be installed" while `rustup target list
# --installed` happily lists it. Doing it here removes the question entirely.
RUN rustup target add wasm32-unknown-unknown && rustup show

# The caches are mounted rather than baked into the layer: a source change then recompiles
# the crates that changed instead of the whole dependency tree, and the few hundred megabytes
# of intermediate artifacts stay out of the image. Anything that must survive into the next
# stage is copied to /out, because a cache mount is not part of the layer.
#
# `--locked` builds exactly the dependency set in Cargo.lock. That is a supply-chain property
# this project treats as load-bearing, not a convenience: an image built from an unreviewed
# resolution is an image nobody can reproduce.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    set -eux; \
    cargo build --release --locked -p cloudpass-server; \
    cargo build --release --locked -p cloudpass-web --target wasm32-unknown-unknown; \
    mkdir -p /out; \
    cp target/release/cloudpass-server /out/; \
    wasm-bindgen --target web --out-dir /out/pkg --no-typescript \
        target/wasm32-unknown-unknown/release/cloudpass_web.wasm; \
    ls -la /out /out/pkg

# ---------------------------------------------------------------------------
# Stage 2: run
# ---------------------------------------------------------------------------

FROM debian:bookworm-slim AS runtime

# `curl` exists for the healthcheck below and nothing else: a container that reports whether
# it is actually serving is worth five megabytes, and `/api/v1/meta` is a public endpoint
# that answers exactly that question.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl; \
    rm -rf /var/lib/apt/lists/*; \
    useradd --system --create-home --uid 10001 cloudpass

WORKDIR /app

COPY --from=builder /out/cloudpass-server /usr/local/bin/cloudpass-server

# The portal: the page's own files — including the typeface, which is served from this origin
# rather than from a font CDN — and the module the builder generated for it. The locale tables
# and the translation machinery are imported by `app.js` at the moment the page loads, so a
# list of files that misses them is not a portal without English: it is a portal that does not
# start at all.
COPY web/web/ui/index.html web/web/ui/app.js web/web/ui/app.css web/web/ui/favicon.svg /app/ui/
COPY web/web/ui/i18n.js web/web/ui/locales-ru.js web/web/ui/locales-en.js /app/ui/
COPY web/web/ui/fonts /app/ui/fonts
# The desktop installer, if one has been built. The directory always exists — it holds a
# `.gitkeep` — so this COPY never fails; when it is empty the server reports that it has no
# build to offer and the landing page shows no download at all.
COPY web/web/ui/download /app/ui/download
COPY --from=builder /out/pkg /app/ui/pkg/

# The database lives outside the image, on a volume. The directory is created and handed to
# the unprivileged user here so that a fresh volume — which Docker creates owned by root —
# is writable on first start.
RUN install -d -o cloudpass -g cloudpass /data

ENV CLOUDPASS_BIND=0.0.0.0:8080 \
    CLOUDPASS_DATABASE_URL=sqlite:///data/cloudpass.db \
    CLOUDPASS_WEB_ROOT=/app/ui \
    RUST_LOG=info

USER cloudpass
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=5 \
    CMD curl -fsS http://127.0.0.1:8080/api/v1/meta || exit 1

ENTRYPOINT ["/usr/local/bin/cloudpass-server"]
