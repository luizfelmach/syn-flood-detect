FROM ubuntu:24.04 AS builder

ARG RUST_TOOLCHAIN=nightly-2026-10-08
ARG BPF_LINKER_VERSION=0.12.0
ENV PATH="/root/.cargo/bin:${PATH}" \
    EBPF_TOOLCHAIN=${RUST_TOOLCHAIN}

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential ca-certificates curl pkg-config zstd \
    && rm -rf /var/lib/apt/lists/*
RUN curl --fail --show-error --location --connect-timeout 15 --max-time 180 --retry 2 https://sh.rustup.rs -o /tmp/rustup-init.sh \
    && sh /tmp/rustup-init.sh -y --profile minimal --default-toolchain "${RUST_TOOLCHAIN}" --component rust-src \
    && rm /tmp/rustup-init.sh
RUN curl --fail --show-error --location --connect-timeout 15 --max-time 180 --retry 2 \
        "https://github.com/aya-rs/bpf-linker/releases/download/v${BPF_LINKER_VERSION}/bpf-linker-x86_64-unknown-linux-musl.tar.zst" \
        -o /tmp/bpf-linker.tar.zst \
    && tar --zstd -xf /tmp/bpf-linker.tar.zst -C /usr/local/bin \
    && rm /tmp/bpf-linker.tar.zst

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY .cargo/ .cargo/
COPY syn-flood-detect/ syn-flood-detect/
COPY syn-flood-detect-common/ syn-flood-detect-common/
COPY syn-flood-detect-ebpf/ syn-flood-detect-ebpf/

RUN cargo build --locked --release --package syn-flood-detect

FROM ubuntu:24.04 AS runtime

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates conntrack curl hping3 iproute2 iptables iputils-ping nginx procps \
        tcpdump tini traceroute util-linux \
    && rm -rf /var/lib/apt/lists/*

COPY --chmod=755 scripts/firewall-start.sh /usr/local/bin/
COPY --from=builder --chmod=755 /build/target/release/syn-flood-detect /usr/local/bin/syn-flood-detect
