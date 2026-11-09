//! Hashes of the detector's fixed 10-byte IPv4 service key.
//! HalfSipHash follows https://github.com/veorq/SipHash (CC0 reference).

pub const HASH_FNV1A: u32 = 0;
pub const HASH_MURMUR3: u32 = 1;
pub const HASH_HALFSIPHASH: u32 = 2;
pub const DEFAULT_HASH_ALGORITHM: u32 = HASH_HALFSIPHASH;
/// Public experimental key, not a secret or a collision-attack defense.
pub const HALFSIPHASH_KEY: [u8; 8] = [0, 1, 2, 3, 4, 5, 6, 7];

#[inline(always)]
pub fn service_key(src: [u8; 4], dst: [u8; 4], port: u16) -> [u8; 10] {
    let port = port.to_be_bytes();
    [
        src[0], src[1], src[2], src[3], dst[0], dst[1], dst[2], dst[3], port[0], port[1],
    ]
}

#[inline(always)]
pub fn fnv1a_32(bytes: &[u8; 10]) -> u32 {
    let mut h = 0x811c_9dc5u32;
    for &byte in bytes {
        h = (h ^ u32::from(byte)).wrapping_mul(0x0100_0193);
    }
    h
}

#[inline(always)]
fn murmur_mix(k: u32) -> u32 {
    k.wrapping_mul(0xcc9e_2d51)
        .rotate_left(15)
        .wrapping_mul(0x1b87_3593)
}

/// MurmurHash3 x86_32, seed zero, specialized for 10 bytes.
#[inline(always)]
pub fn murmur3_x86_32(bytes: &[u8; 10]) -> u32 {
    let mut h = 0u32;
    for i in [0, 4] {
        h ^= murmur_mix(u32::from_le_bytes([
            bytes[i],
            bytes[i + 1],
            bytes[i + 2],
            bytes[i + 3],
        ]));
        h = h.rotate_left(13).wrapping_mul(5).wrapping_add(0xe654_6b64);
    }
    h ^= murmur_mix(u32::from(bytes[8]) | (u32::from(bytes[9]) << 8));
    h ^= 10;
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^ (h >> 16)
}

#[inline(always)]
fn halfsip_round(v: &mut [u32; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(5) ^ v[0];
    v[0] = v[0].rotate_left(16);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(8) ^ v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(7) ^ v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(13) ^ v[2];
    v[2] = v[2].rotate_left(16);
}

/// HalfSipHash-2-4-32 with the fixed experimental key above.
#[inline(always)]
pub fn halfsiphash_2_4_32(bytes: &[u8; 10]) -> u32 {
    let k = HALFSIPHASH_KEY;
    let k0 = u32::from_le_bytes([k[0], k[1], k[2], k[3]]);
    let k1 = u32::from_le_bytes([k[4], k[5], k[6], k[7]]);
    let mut v = [k0, k1, 0x6c79_6765 ^ k0, 0x7465_6462 ^ k1];
    let words = [
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        (10 << 24) | u32::from(bytes[8]) | (u32::from(bytes[9]) << 8),
    ];
    for m in words {
        v[3] ^= m;
        halfsip_round(&mut v);
        halfsip_round(&mut v);
        v[0] ^= m;
    }
    v[2] ^= 0xff;
    for _ in 0..4 {
        halfsip_round(&mut v);
    }
    v[1] ^ v[3]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_vectors() {
        // HalfSipHash and MurmurHash3 outputs verified against the authors' C/C++
        // implementations; FNV-1a preserves the previous detector's byte order.
        let vectors = [
            (
                [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
                [0x2f854072, 0xd5ba5efb, 0x3479b094],
            ),
            ([0; 10], [0x404ba46d, 0x20217e1b, 0xc7db4d87]),
            ([255; 10], [0x98b90efb, 0xf0405b4c, 0x49a1bbac]),
            (
                service_key([104, 0, 1, 1], [203, 0, 113, 2], 80),
                [0xc2510467, 0x9fa27885, 0xb92cd411],
            ),
        ];
        for (input, expected) in vectors {
            assert_eq!(
                [
                    fnv1a_32(&input),
                    murmur3_x86_32(&input),
                    halfsiphash_2_4_32(&input)
                ],
                expected
            );
        }
        assert_eq!(DEFAULT_HASH_ALGORITHM, HASH_HALFSIPHASH);
    }
}
