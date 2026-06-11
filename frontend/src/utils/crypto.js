/**
 * Web Crypto API utilities for key generation
 * Supports RSA-2048/3072 and ECC P-256/P-384
 */

export const ALGORITHMS = {
  RSA_2048: {
    name: 'RSA-OAEP',
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-256'
  },
  RSA_3072: {
    name: 'RSA-OAEP',
    modulusLength: 3072,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-256'
  },
  ECC_P256: {
    name: 'ECDSA',
    namedCurve: 'P-256'
  },
  ECC_P384: {
    name: 'ECDSA',
    namedCurve: 'P-384'
  }
};

/**
 * Generate asymmetric key pair
 */
export async function generateKeyPair(algorithm = 'RSA_2048') {
  const config = ALGORITHMS[algorithm];

  if (!config) {
    throw new Error(`Invalid algorithm: ${algorithm}`);
  }

  const keyPair = await window.crypto.subtle.generateKey(
    config,
    true,
    algorithm.startsWith('RSA') ? ['encrypt', 'decrypt'] : ['sign', 'verify']
  );

  console.log(`Generated ${algorithm} key pair`);
  return keyPair;
}

/**
 * Export public key to JWK
 */
export async function exportPublicKey(publicKey) {
  const jwk = await window.crypto.subtle.exportKey('jwk', publicKey);
  return jwk;
}

/**
 * Export private key to JWK
 */
export async function exportPrivateKey(privateKey) {
  const jwk = await window.crypto.subtle.exportKey('jwk', privateKey);
  return jwk;
}

/**
 * Import public key from JWK
 */
export async function importPublicKey(jwk, algorithm = 'RSA_2048') {
  const config = ALGORITHMS[algorithm];

  const publicKey = await window.crypto.subtle.importKey(
    'jwk',
    jwk,
    config,
    true,
    algorithm.startsWith('RSA') ? ['encrypt'] : ['verify']
  );

  return publicKey;
}

/**
 * Import private key from JWK
 */
export async function importPrivateKey(jwk, algorithm = 'RSA_2048') {
  const config = ALGORITHMS[algorithm];

  const privateKey = await window.crypto.subtle.importKey(
    'jwk',
    jwk,
    config,
    true,
    algorithm.startsWith('RSA') ? ['decrypt'] : ['sign']
  );

  return privateKey;
}

/**
 * Generate key fingerprint (SHA-256 hash of public key)
 */
export async function getKeyFingerprint(publicKey) {
  const jwk = await exportPublicKey(publicKey);
  const jwkString = JSON.stringify(jwk);
  const encoder = new TextEncoder();
  const data = encoder.encode(jwkString);

  const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const fingerprint = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

  return fingerprint;
}
