#!/usr/bin/env bash
set -Eeuo pipefail

[[ -x /usr/local/bin/syn-flood-detect ]] || {
    echo 'firewall: missing eBPF executable; rebuild with make build.' >&2
    exit 1
}

trap 'exit 143' TERM
trap 'exit 130' INT
deadline=$((SECONDS + 60))
until [[ -e /run/firewall-network-ready ]]; do
    if (( SECONDS >= deadline )); then
        echo 'firewall: timed out waiting for network configuration (60s).' >&2
        exit 1
    fi
    sleep 1
done

export RUST_LOG=${RUST_LOG:-info}
exec /usr/local/bin/syn-flood-detect run --iface eth1 --packet-dir /var/log/syn-flood-detect \
    --hash-algorithm "${HASH_ALGORITHM:-halfsiphash}"
