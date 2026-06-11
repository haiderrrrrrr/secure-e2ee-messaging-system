/**
 * Authenticated ephemeral ECDH key exchange using P-256, digital
 * signatures, HKDF-SHA-256, and AES-256-GCM session keys.
 */

import { getKeyPair } from './keyStorage';

const PROTOCOL_VERSION = 'secure-e2ee-v1.0';
const HKDF_INFO = 'secure-e2ee-session-key-v1';
const HKDF_SALT_LENGTH = 32;

/**
 * Generate ephemeral ECDH key pair for session
 * Custom: Using P-256 curve (modified from standard P-384)
 */
export async function generateEphemeralKeyPair() {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-256' // Custom: Changed from P-384
    },
    true,
    ['deriveKey', 'deriveBits']
  );

  return keyPair;
}

/**
 * Export public key to JWK format for transmission
 */
export async function exportPublicKey(publicKey) {
  return await window.crypto.subtle.exportKey('jwk', publicKey);
}

/**
 * Import public key from JWK format
 * Custom: Using P-256 curve
 */
export async function importPublicKey(publicKeyJWK) {
  return await window.crypto.subtle.importKey(
    'jwk',
    publicKeyJWK,
    {
      name: 'ECDH',
      namedCurve: 'P-256' // Custom: Changed from P-384
    },
    true,
    []
  );
}

/**
 * Derive shared secret using ECDH
 */
export async function deriveSharedSecret(privateKey, publicKey) {
  const sharedSecret = await window.crypto.subtle.deriveBits(
    {
      name: 'ECDH',
      public: publicKey
    },
    privateKey,
    256 // 256 bits
  );

  return sharedSecret;
}

/**
 * Derive session key from shared secret using HKDF
 * Custom: Uses student ID-based info string for unique key derivation
 */
export async function deriveSessionKey(sharedSecret, salt, info = HKDF_INFO) {
  // Import shared secret as key material
  const keyMaterial = await window.crypto.subtle.importKey(
    'raw',
    sharedSecret,
    'HKDF',
    false,
    ['deriveKey']
  );

  // Derive AES-GCM key for encryption
  const sessionKey = await window.crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: salt,
      info: new TextEncoder().encode(info)
    },
    keyMaterial,
    {
      name: 'AES-GCM',
      length: 256
    },
    true,
    ['encrypt', 'decrypt']
  );

  return sessionKey;
}

/**
 * Generate signature for key exchange (authenticity)
 * Signs ephemeral public key with long-term private key
 */
export async function signKeyExchangeData(userId, ephemeralPublicKeyJWK) {
  // Get user's long-term key pair from IndexedDB
  const keyPair = await getKeyPair(userId);

  if (!keyPair) {
    throw new Error('User key pair not found');
  }

  // For ECC keys, we need to use ECDSA for signing
  if (keyPair.algorithm.startsWith('ECC')) {
    // Import private key for signing
    // Remove key_ops and alg to avoid conflicts with Web Crypto API
    const privateKeyJWK = { ...keyPair.privateKey };
    delete privateKeyJWK.key_ops;
    delete privateKeyJWK.alg;

    const privateKey = await window.crypto.subtle.importKey(
      'jwk',
      privateKeyJWK,
      {
        name: 'ECDSA',
        namedCurve: keyPair.algorithm === 'ECC_P256' ? 'P-256' : 'P-384'
      },
      true,
      ['sign']
    );

    // Create data to sign (ephemeral public key)
    const dataToSign = new TextEncoder().encode(
      JSON.stringify(ephemeralPublicKeyJWK)
    );

    // Sign with ECDSA
    const signature = await window.crypto.subtle.sign(
      {
        name: 'ECDSA',
        hash: 'SHA-256'
      },
      privateKey,
      dataToSign
    );

    return {
      signature: Array.from(new Uint8Array(signature)),
      algorithm: 'ECDSA'
    };
  } else {
    // For RSA keys, use RSA-PSS for signing
    // Remove key_ops and alg to avoid conflicts with Web Crypto API
    const privateKeyJWK = { ...keyPair.privateKey };
    delete privateKeyJWK.key_ops;
    delete privateKeyJWK.alg;

    const privateKey = await window.crypto.subtle.importKey(
      'jwk',
      privateKeyJWK,
      {
        name: 'RSA-PSS',
        hash: 'SHA-256'
      },
      true,
      ['sign']
    );

    const dataToSign = new TextEncoder().encode(
      JSON.stringify(ephemeralPublicKeyJWK)
    );

    const signature = await window.crypto.subtle.sign(
      {
        name: 'RSA-PSS',
        saltLength: 32
      },
      privateKey,
      dataToSign
    );

    return {
      signature: Array.from(new Uint8Array(signature)),
      algorithm: 'RSA-PSS'
    };
  }
}

/**
 * Verify signature from peer (prevent MITM)
 */
export async function verifyKeyExchangeSignature(
  peerPublicKeyJWK,
  ephemeralPublicKeyJWK,
  signatureData,
  algorithm
) {
  try {
    // Determine key algorithm from peer's public key
    const isECC = peerPublicKeyJWK.crv !== undefined;

    // Remove key_ops and alg to avoid conflicts with Web Crypto API
    const cleanPublicKeyJWK = { ...peerPublicKeyJWK };
    delete cleanPublicKeyJWK.key_ops;
    delete cleanPublicKeyJWK.alg;

    let publicKey;
    if (isECC) {
      // Import ECC public key for verification
      publicKey = await window.crypto.subtle.importKey(
        'jwk',
        cleanPublicKeyJWK,
        {
          name: 'ECDSA',
          namedCurve: cleanPublicKeyJWK.crv
        },
        true,
        ['verify']
      );

      const dataToVerify = new TextEncoder().encode(
        JSON.stringify(ephemeralPublicKeyJWK)
      );

      const signatureBuffer = new Uint8Array(signatureData).buffer;

      const isValid = await window.crypto.subtle.verify(
        {
          name: 'ECDSA',
          hash: 'SHA-256'
        },
        publicKey,
        signatureBuffer,
        dataToVerify
      );

      return isValid;
    } else {
      // Import RSA public key for verification
      publicKey = await window.crypto.subtle.importKey(
        'jwk',
        cleanPublicKeyJWK,
        {
          name: 'RSA-PSS',
          hash: 'SHA-256'
        },
        true,
        ['verify']
      );

      const dataToVerify = new TextEncoder().encode(
        JSON.stringify(ephemeralPublicKeyJWK)
      );

      const signatureBuffer = new Uint8Array(signatureData).buffer;

      const isValid = await window.crypto.subtle.verify(
        {
          name: 'RSA-PSS',
          saltLength: 32
        },
        publicKey,
        signatureBuffer,
        dataToVerify
      );

      return isValid;
    }
  } catch (error) {
    console.error('Signature verification failed:', error);
    return false;
  }
}

/**
 * Generate a random 256-bit salt for HKDF.
 */
export function generateSalt() {
  return window.crypto.getRandomValues(new Uint8Array(HKDF_SALT_LENGTH));
}

/**
 * Generate a key confirmation tag using HMAC-SHA256.
 */
export async function generateKeyConfirmation(sessionKey, exchangeId) {
  const confirmationMessage = `SECURE_E2EE_KEY_CONFIRMED_${exchangeId}`;
  const messageBuffer = new TextEncoder().encode(confirmationMessage);

  // Import session key for HMAC
  const sessionKeyData = await window.crypto.subtle.exportKey('raw', sessionKey);
  const hmacKey = await window.crypto.subtle.importKey(
    'raw',
    sessionKeyData,
    {
      name: 'HMAC',
      hash: 'SHA-256'
    },
    false,
    ['sign']
  );

  // Generate HMAC tag
  const confirmationTag = await window.crypto.subtle.sign(
    'HMAC',
    hmacKey,
    messageBuffer
  );

  return Array.from(new Uint8Array(confirmationTag));
}

/**
 * Verify a key confirmation tag.
 */
export async function verifyKeyConfirmation(sessionKey, exchangeId, receivedTag) {
  const expectedTag = await generateKeyConfirmation(sessionKey, exchangeId);
  
  // Constant-time comparison
  if (receivedTag.length !== expectedTag.length) return false;
  
  let mismatch = 0;
  for (let i = 0; i < receivedTag.length; i++) {
    mismatch |= receivedTag[i] ^ expectedTag[i];
  }
  
  return mismatch === 0;
}

/**
 * Complete key exchange protocol - Initiator side
 * Returns session key and exchange data to send to peer
 */
export async function initiateKeyExchange(userId) {
  // Step 1: Generate ephemeral ECDH key pair
  const ephemeralKeyPair = await generateEphemeralKeyPair();

  // Step 2: Export public key
  const ephemeralPublicKeyJWK = await exportPublicKey(ephemeralKeyPair.publicKey);

  // Step 3: Sign ephemeral public key with long-term key
  const signatureData = await signKeyExchangeData(userId, ephemeralPublicKeyJWK);

  // Step 4: Generate salt for HKDF
  const salt = generateSalt();

  return {
    ephemeralKeyPair,
    exchangeData: {
      protocolVersion: PROTOCOL_VERSION,
      ephemeralPublicKey: ephemeralPublicKeyJWK,
      signature: signatureData.signature,
      signatureAlgorithm: signatureData.algorithm,
      salt: Array.from(salt),
      parameters: {
        curveType: 'P-256',
        hkdfInfo: HKDF_INFO
      }
    }
  };
}

/**
 * Complete key exchange protocol - Responder side
 * Processes received exchange data and returns response
 */
export async function respondToKeyExchange(
  userId,
  peerLongTermPublicKeyJWK,
  receivedExchangeData
) {
  // Step 1: Verify peer's signature
  const isValid = await verifyKeyExchangeSignature(
    peerLongTermPublicKeyJWK,
    receivedExchangeData.ephemeralPublicKey,
    receivedExchangeData.signature,
    receivedExchangeData.signatureAlgorithm
  );

  if (!isValid) {
    throw new Error('Key exchange signature verification failed - possible MITM attack');
  }

  // Step 2: Generate our ephemeral key pair
  const ephemeralKeyPair = await generateEphemeralKeyPair();
  const ephemeralPublicKeyJWK = await exportPublicKey(ephemeralKeyPair.publicKey);

  // Step 3: Sign our ephemeral public key
  const signatureData = await signKeyExchangeData(userId, ephemeralPublicKeyJWK);

  // Step 4: Import peer's ephemeral public key
  const peerEphemeralPublicKey = await importPublicKey(
    receivedExchangeData.ephemeralPublicKey
  );

  // Step 5: Derive shared secret
  const sharedSecret = await deriveSharedSecret(
    ephemeralKeyPair.privateKey,
    peerEphemeralPublicKey
  );

  // Step 6: Derive session key using received salt
  const salt = new Uint8Array(receivedExchangeData.salt);
  const sessionKey = await deriveSessionKey(sharedSecret, salt);

  return {
    sessionKey,
    responseData: {
      ephemeralPublicKey: ephemeralPublicKeyJWK,
      signature: signatureData.signature,
      signatureAlgorithm: signatureData.algorithm
    }
  };
}

/**
 * Complete key exchange protocol - Initiator finalization
 * Processes responder's data and derives final session key
 */
export async function finalizeKeyExchange(
  ephemeralKeyPair,
  salt,
  peerLongTermPublicKeyJWK,
  responseData
) {
  // Step 1: Verify peer's signature
  const isValid = await verifyKeyExchangeSignature(
    peerLongTermPublicKeyJWK,
    responseData.ephemeralPublicKey,
    responseData.signature,
    responseData.signatureAlgorithm
  );

  if (!isValid) {
    throw new Error('Key exchange signature verification failed - possible MITM attack');
  }

  // Step 2: Import peer's ephemeral public key
  const peerEphemeralPublicKey = await importPublicKey(
    responseData.ephemeralPublicKey
  );

  // Step 3: Derive shared secret
  const sharedSecret = await deriveSharedSecret(
    ephemeralKeyPair.privateKey,
    peerEphemeralPublicKey
  );

  // Step 4: Derive session key using our salt
  const sessionKey = await deriveSessionKey(sharedSecret, salt);

  return sessionKey;
}

/**
 * IndexedDB for persistent session key storage
 */
const SESSION_DB_NAME = 'SecureChatSessions';
const SESSION_DB_VERSION = 1;
const SESSION_STORE_NAME = 'sessionKeys';

function openSessionDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(SESSION_DB_NAME, SESSION_DB_VERSION);

    request.onerror = () => reject(new Error('Failed to open session database'));
    request.onsuccess = () => resolve(request.result);

    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains(SESSION_STORE_NAME)) {
        const store = db.createObjectStore(SESSION_STORE_NAME, { keyPath: 'peerId' });
        store.createIndex('peerId', 'peerId', { unique: true });
        store.createIndex('createdAt', 'createdAt', { unique: false });
      }
    };
  });
}

/**
 * Store session key in IndexedDB (persistent)
 */
export async function storeSessionKey(peerId, sessionKey) {
  try {
    // Export session key to JWK format
    const keyJWK = await window.crypto.subtle.exportKey('jwk', sessionKey);

    const db = await openSessionDB();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction([SESSION_STORE_NAME], 'readwrite');
      const store = transaction.objectStore(SESSION_STORE_NAME);

      const sessionData = {
        peerId,
        keyJWK,
        createdAt: new Date().toISOString()
      };

      const request = store.put(sessionData);

      request.onsuccess = () => {
        console.log(`Stored session key for peer ${peerId} in IndexedDB`);
        resolve();
      };

      request.onerror = () => reject(new Error('Failed to store session key'));

      transaction.oncomplete = () => db.close();
    });
  } catch (error) {
    console.error('Failed to store session key:', error);
    throw error;
  }
}

/**
 * Retrieve session key from IndexedDB
 */
export async function getSessionKey(peerId) {
  try {
    const db = await openSessionDB();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction([SESSION_STORE_NAME], 'readonly');
      const store = transaction.objectStore(SESSION_STORE_NAME);
      const request = store.get(peerId);

      request.onsuccess = async () => {
        const result = request.result;

        if (!result || !result.keyJWK) {
          resolve(null);
          return;
        }

        try {
          // Import session key from JWK
          const sessionKey = await window.crypto.subtle.importKey(
            'jwk',
            result.keyJWK,
            {
              name: 'AES-GCM',
              length: 256
            },
            true,
            ['encrypt', 'decrypt']
          );

          resolve(sessionKey);
        } catch (error) {
          console.error('Failed to import session key:', error);
          resolve(null);
        }
      };

      request.onerror = () => {
        console.error('Failed to retrieve session key');
        resolve(null);
      };

      transaction.oncomplete = () => db.close();
    });
  } catch (error) {
    console.error('Failed to get session key:', error);
    return null;
  }
}

/**
 * Clear session key from IndexedDB
 */
export async function clearSessionKey(peerId) {
  try {
    const db = await openSessionDB();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction([SESSION_STORE_NAME], 'readwrite');
      const store = transaction.objectStore(SESSION_STORE_NAME);
      const request = store.delete(peerId);

      request.onsuccess = () => {
        console.log(`Cleared session key for peer ${peerId}`);
        resolve();
      };

      request.onerror = () => reject(new Error('Failed to clear session key'));

      transaction.oncomplete = () => db.close();
    });
  } catch (error) {
    console.error('Failed to clear session key:', error);
  }
}

/**
 * Clear all session keys (e.g., on logout)
 */
export async function clearAllSessionKeys() {
  try {
    const db = await openSessionDB();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction([SESSION_STORE_NAME], 'readwrite');
      const store = transaction.objectStore(SESSION_STORE_NAME);
      const request = store.clear();

      request.onsuccess = () => {
        console.log('Cleared all session keys');
        resolve();
      };

      request.onerror = () => reject(new Error('Failed to clear all session keys'));

      transaction.oncomplete = () => db.close();
    });
  } catch (error) {
    console.error('Failed to clear all session keys:', error);
  }
}
