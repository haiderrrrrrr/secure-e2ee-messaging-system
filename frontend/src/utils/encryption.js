/**
 * Message Encryption/Decryption using AES-256-GCM
 * Uses session keys established via ECDH key exchange
 */

/**
 * Encrypt a text message using AES-256-GCM
 * @param {string} plaintext - The message to encrypt
 * @param {CryptoKey} sessionKey - The AES-GCM session key
 * @returns {Object} - { ciphertext: base64, iv: base64, authTag: base64 }
 */
export async function encryptMessage(plaintext, sessionKey) {
  // Generate random IV (12 bytes for GCM)
  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  // Convert plaintext to ArrayBuffer
  const encoder = new TextEncoder();
  const plaintextBuffer = encoder.encode(plaintext);

  // Encrypt with AES-256-GCM
  const ciphertextBuffer = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
      tagLength: 128 // 128-bit authentication tag
    },
    sessionKey,
    plaintextBuffer
  );

  // The ciphertext includes the auth tag at the end (last 16 bytes)
  const ciphertext = new Uint8Array(ciphertextBuffer);

  return {
    ciphertext: arrayBufferToBase64(ciphertext),
    iv: arrayBufferToBase64(iv),
    // Auth tag is included in ciphertext by Web Crypto API
  };
}

/**
 * Decrypt a message using AES-256-GCM
 * @param {string} ciphertextBase64 - Base64 encoded ciphertext (includes auth tag)
 * @param {string} ivBase64 - Base64 encoded IV
 * @param {CryptoKey} sessionKey - The AES-GCM session key
 * @returns {string} - Decrypted plaintext
 */
export async function decryptMessage(ciphertextBase64, ivBase64, sessionKey) {
  try {
    // Convert from base64 to ArrayBuffer
    const ciphertext = base64ToArrayBuffer(ciphertextBase64);
    const iv = base64ToArrayBuffer(ivBase64);

    // Decrypt with AES-256-GCM (automatically verifies auth tag)
    const plaintextBuffer = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128
      },
      sessionKey,
      ciphertext
    );

    // Convert ArrayBuffer to string
    const decoder = new TextDecoder();
    const plaintext = decoder.decode(plaintextBuffer);

    return plaintext;
  } catch (error) {
    console.error('Decryption failed:', error);
    throw new Error('Message decryption failed - authentication tag verification failed or wrong key');
  }
}

/**
 * Encrypt a file using AES-256-GCM
 * @param {File} file - The file to encrypt
 * @param {CryptoKey} sessionKey - The AES-GCM session key
 * @returns {Object} - { encryptedData: base64, iv: base64, fileName: string, fileType: string, fileSize: number }
 */
export async function encryptFile(file, sessionKey) {
  // Generate random IV
  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  // Read file as ArrayBuffer
  const fileBuffer = await file.arrayBuffer();

  // Encrypt file data
  const encryptedBuffer = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
      tagLength: 128
    },
    sessionKey,
    fileBuffer
  );

  const encryptedData = new Uint8Array(encryptedBuffer);

  return {
    encryptedData: arrayBufferToBase64(encryptedData),
    iv: arrayBufferToBase64(iv),
    fileName: file.name,
    fileType: file.type,
    fileSize: file.size
  };
}

/**
 * Decrypt a file using AES-256-GCM
 * @param {string} encryptedDataBase64 - Base64 encoded encrypted file data
 * @param {string} ivBase64 - Base64 encoded IV
 * @param {CryptoKey} sessionKey - The AES-GCM session key
 * @param {string} fileName - Original file name
 * @param {string} fileType - Original file MIME type
 * @returns {Blob} - Decrypted file as Blob
 */
export async function decryptFile(encryptedDataBase64, ivBase64, sessionKey, fileName, fileType) {
  try {
    // Convert from base64 to ArrayBuffer
    const encryptedData = base64ToArrayBuffer(encryptedDataBase64);
    const iv = base64ToArrayBuffer(ivBase64);

    // Decrypt file data
    const decryptedBuffer = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128
      },
      sessionKey,
      encryptedData
    );

    // Create Blob from decrypted data
    const blob = new Blob([decryptedBuffer], { type: fileType });

    return blob;
  } catch (error) {
    console.error('File decryption failed:', error);
    throw new Error('File decryption failed - authentication tag verification failed or wrong key');
  }
}

/**
 * Helper: Convert ArrayBuffer to Base64
 */
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

/**
 * Helper: Convert Base64 to ArrayBuffer
 */
function base64ToArrayBuffer(base64) {
  const binary = window.atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Generate message hash for verification (optional)
 */
export async function generateMessageHash(message) {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}
