/**
 * Schnorr ZKP Math Utilities
 * Using BigInt for modular arithmetic.
 */

// A safe prime 'p' and generator 'g' for the group.
// For a real production app, use a standard 2048-bit or 3072-bit MODP group (e.g., RFC 3526).
// For this demo, we use a smaller but functional 1024-bit prime.
export const P = BigInt(
  "0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
);
export const G = BigInt(2);
export const Q = (P - 1n) / 2n; // The order of the subgroup if using a safe prime

/**
 * Modular Exponentiation: (base ^ exp) % mod
 */
export function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let res = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp % 2n === 1n) res = (res * base) % mod;
    base = (base * base) % mod;
    exp = exp / 2n;
  }
  return res;
}

/**
 * Generate a random BigInt in range [1, limit-1]
 * Works in both Browser and Node.js 19+ using globalThis.crypto
 */
export function randomBigInt(limit: bigint): bigint {
  const byteLength = Math.ceil(limit.toString(16).length / 2) + 1;
  let r: bigint;
  const bytes = new Uint8Array(byteLength);

  do {
    globalThis.crypto.getRandomValues(bytes);
    let hex = "";
    bytes.forEach((b) => (hex += b.toString(16).padStart(2, "0")));
    r = BigInt("0x" + hex);
  } while (r <= 0n || r >= limit);

  return r;
}
