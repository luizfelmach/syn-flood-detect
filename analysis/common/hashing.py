"""Detector hashes over the 10-byte IPv4 service key (wrapping u32 arithmetic)."""

MASK = 0xFFFFFFFF
ALGORITHMS = ("fnv1a", "murmur3", "halfsiphash")
DEFAULT_HASH_ALGORITHM = "halfsiphash"
HALFSIPHASH_KEY = bytes(range(8))  # Public, fixed experimental key; matches Rust.


def rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & MASK


def fnv1a_32(data):
    h = 0x811C9DC5
    for byte in data:
        h = ((h ^ byte) * 0x01000193) & MASK
    return h


def murmur3_x86_32(data):
    def mix(k):
        return (rotl((k * 0xCC9E2D51) & MASK, 15) * 0x1B873593) & MASK

    h = 0
    end = len(data) - len(data) % 4
    for offset in range(0, end, 4):
        h ^= mix(int.from_bytes(data[offset:offset + 4], "little"))
        h = (rotl(h, 13) * 5 + 0xE6546B64) & MASK
    h ^= mix(int.from_bytes(data[end:], "little"))
    h ^= len(data)
    h = ((h ^ (h >> 16)) * 0x85EBCA6B) & MASK
    h = ((h ^ (h >> 13)) * 0xC2B2AE35) & MASK
    return h ^ (h >> 16)


def halfsiphash_2_4_32(data):
    def sipround(v):
        a, b, c, d = v
        a = (a + b) & MASK
        b = rotl(b, 5) ^ a
        a = rotl(a, 16)
        c = (c + d) & MASK
        d = rotl(d, 8) ^ c
        a = (a + d) & MASK
        d = rotl(d, 7) ^ a
        c = (c + b) & MASK
        b = rotl(b, 13) ^ c
        return [a, b, rotl(c, 16), d]

    k0 = int.from_bytes(HALFSIPHASH_KEY[:4], "little")
    k1 = int.from_bytes(HALFSIPHASH_KEY[4:], "little")
    v = [k0, k1, 0x6C796765 ^ k0, 0x74656462 ^ k1]
    end = len(data) - len(data) % 4
    words = [int.from_bytes(data[i:i + 4], "little") for i in range(0, end, 4)]
    words.append(((len(data) & 0xFF) << 24) | int.from_bytes(data[end:], "little"))
    for word in words:
        v[3] ^= word
        v = sipround(sipround(v))
        v[0] ^= word
    v[2] ^= 0xFF
    for _ in range(4):
        v = sipround(v)
    return v[1] ^ v[3]


HASH_FUNCTIONS = dict(zip(ALGORITHMS, (fnv1a_32, murmur3_x86_32, halfsiphash_2_4_32)))
