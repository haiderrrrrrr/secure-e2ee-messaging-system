/**
 * IndexedDB storage for private keys
 * Private keys stored locally, NEVER sent to server
 */

const DB_NAME = 'SecureChatKeys';
const DB_VERSION = 1;
const STORE_NAME = 'keyPairs';

function openDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onerror = () => reject(new Error('Failed to open IndexedDB'));
    request.onsuccess = () => resolve(request.result);

    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        const store = db.createObjectStore(STORE_NAME, { keyPath: 'userId' });
        store.createIndex('userId', 'userId', { unique: true });
      }
    };
  });
}

/**
 * Store key pair in IndexedDB
 */
export async function storeKeyPair(userId, privateKeyJWK, publicKeyJWK, algorithm) {
  const db = await openDB();

  return new Promise((resolve, reject) => {
    const transaction = db.transaction([STORE_NAME], 'readwrite');
    const store = transaction.objectStore(STORE_NAME);

    const keyData = {
      userId,
      privateKey: privateKeyJWK,
      publicKey: publicKeyJWK,
      algorithm,
      createdAt: new Date().toISOString()
    };

    const request = store.put(keyData);

    request.onsuccess = () => {
      console.log(`Stored key pair for user ${userId} in IndexedDB`);
      resolve();
    };

    request.onerror = () => reject(new Error('Failed to store key pair'));

    transaction.oncomplete = () => db.close();
  });
}

/**
 * Retrieve key pair from IndexedDB
 */
export async function getKeyPair(userId) {
  const db = await openDB();

  return new Promise((resolve, reject) => {
    const transaction = db.transaction([STORE_NAME], 'readonly');
    const store = transaction.objectStore(STORE_NAME);
    const request = store.get(userId);

    request.onsuccess = () => {
      resolve(request.result || null);
    };

    request.onerror = () => reject(new Error('Failed to retrieve key pair'));

    transaction.oncomplete = () => db.close();
  });
}

/**
 * Check if key pair exists
 */
export async function hasKeyPair(userId) {
  const keyPair = await getKeyPair(userId);
  return keyPair !== null;
}

/**
 * Delete key pair from IndexedDB
 */
export async function deleteKeyPair(userId) {
  const db = await openDB();

  return new Promise((resolve, reject) => {
    const transaction = db.transaction([STORE_NAME], 'readwrite');
    const store = transaction.objectStore(STORE_NAME);
    const request = store.delete(userId);

    request.onsuccess = () => {
      console.log(`Deleted key pair for user ${userId}`);
      resolve();
    };

    request.onerror = () => reject(new Error('Failed to delete key pair'));

    transaction.oncomplete = () => db.close();
  });
}
