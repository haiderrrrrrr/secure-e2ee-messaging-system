/**
 * Frontend Replay Attack Protection Utilities
 *
 * Generates and manages:
 * 1. Nonces - Cryptographically random unique identifiers
 * 2. Timestamps - ISO 8601 format timestamps
 * 3. Sequence Numbers - Per-conversation monotonic counters
 */

// Store sequence numbers per conversation in memory
const conversationSequences = new Map();

/**
 * Generate a cryptographically secure nonce
 * Format: timestamp_randomHex_randomInt
 */
export function generateNonce() {
  const timestamp = Date.now();

  // Generate random bytes
  const randomArray = new Uint8Array(16);
  window.crypto.getRandomValues(randomArray);
  const randomHex = Array.from(randomArray)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  // Generate random counter
  const randomInt = window.crypto.getRandomValues(new Uint32Array(1))[0];

  return `${timestamp}_${randomHex}_${randomInt}`;
}

/**
 * Get current timestamp in ISO 8601 format
 */
export function getCurrentTimestamp() {
  return new Date().toISOString();
}

/**
 * Initialize sequence counter for a conversation
 */
export function initializeSequenceCounter(contactId, startingSequence = 0) {
  conversationSequences.set(contactId, startingSequence);
}

/**
 * Get next sequence number for a conversation
 * Automatically increments the counter
 */
export function getNextSequenceNumber(contactId) {
  if (!conversationSequences.has(contactId)) {
    // Initialize at 1 if not exists
    conversationSequences.set(contactId, 1);
    return 1;
  }

  const current = conversationSequences.get(contactId);
  const next = current + 1;
  conversationSequences.set(contactId, next);

  return next;
}

/**
 * Get current sequence number without incrementing
 */
export function getCurrentSequenceNumber(contactId) {
  return conversationSequences.get(contactId) || 0;
}

/**
 * Reset sequence counter for a conversation
 * (Useful when starting a new key exchange)
 */
export function resetSequenceCounter(contactId) {
  conversationSequences.set(contactId, 0);
}

/**
 * Sync sequence number from server
 * Updates local counter to match server state
 */
export function syncSequenceNumber(contactId, serverSequence) {
  const current = getCurrentSequenceNumber(contactId);

  if (serverSequence > current) {
    conversationSequences.set(contactId, serverSequence);
    console.log(`Synced sequence for ${contactId}: ${current} → ${serverSequence}`);
  }
}

/**
 * Create message metadata with replay protection
 */
export function createMessageMetadata(contactId) {
  return {
    nonce: generateNonce(),
    messageSequence: getNextSequenceNumber(contactId),
    timestamp: getCurrentTimestamp()
  };
}

/**
 * Validate incoming message metadata (basic checks)
 */
export function validateIncomingMessage(metadata, contactId) {
  const errors = [];

  // Check if nonce exists
  if (!metadata.nonce) {
    errors.push('Missing nonce');
  }

  // Check if timestamp exists and is recent
  if (!metadata.timestamp) {
    errors.push('Missing timestamp');
  } else {
    const messageTime = new Date(metadata.timestamp).getTime();
    const now = Date.now();
    const fiveMinutes = 5 * 60 * 1000;

    if (now - messageTime > fiveMinutes) {
      errors.push('Message timestamp is too old');
    }

    if (messageTime > now + 30000) {
      errors.push('Message timestamp is from the future');
    }
  }

  // Check sequence number
  if (typeof metadata.messageSequence !== 'number') {
    errors.push('Invalid or missing sequence number');
  } else {
    const expected = getCurrentSequenceNumber(contactId);
    if (metadata.messageSequence <= expected) {
      errors.push(`Sequence number must be > ${expected}, got ${metadata.messageSequence}`);
    }
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Clear all sequence counters (e.g., on logout)
 */
export function clearAllSequenceCounters() {
  conversationSequences.clear();
}

/**
 * Get all conversation sequences (for debugging)
 */
export function getAllSequences() {
  return Object.fromEntries(conversationSequences);
}

/**
 * Persist sequence counters to localStorage
 */
export function saveSequencesToStorage(userId) {
  try {
    const sequences = Object.fromEntries(conversationSequences);
    localStorage.setItem(`sequences_${userId}`, JSON.stringify(sequences));
  } catch (error) {
    console.error('Failed to save sequences to storage:', error);
  }
}

/**
 * Load sequence counters from localStorage
 */
export function loadSequencesFromStorage(userId) {
  try {
    const stored = localStorage.getItem(`sequences_${userId}`);
    if (stored) {
      const sequences = JSON.parse(stored);
      Object.entries(sequences).forEach(([contactId, sequence]) => {
        conversationSequences.set(contactId, sequence);
      });
      console.log('Loaded sequence counters from storage:', sequences);
    }
  } catch (error) {
    console.error('Failed to load sequences from storage:', error);
  }
}
