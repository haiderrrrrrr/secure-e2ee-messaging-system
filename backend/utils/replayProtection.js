const crypto = require('crypto');
const Message = require('../models/Message');

/**
 * Replay Attack Protection Utilities
 *
 * Protection Mechanisms:
 * 1. Nonces - Cryptographically random, never reused
 * 2. Timestamps - Messages must be recent (within time window)
 * 3. Sequence Numbers - Monotonically increasing per conversation
 * 4. Combined Verification - All three must pass
 */

// Time window for accepting messages (5 minutes)
const MESSAGE_TIME_WINDOW_MS = 5 * 60 * 1000;

// Maximum allowed clock skew (30 seconds)
const MAX_CLOCK_SKEW_MS = 30 * 1000;

/**
 * Generate a cryptographically secure nonce
 * Nonce format: timestamp_randomBytes_counter
 */
function generateNonce() {
  const timestamp = Date.now();
  const randomBytes = crypto.randomBytes(16).toString('hex');
  const counter = crypto.randomInt(0, 1000000);
  return `${timestamp}_${randomBytes}_${counter}`;
}

/**
 * Validate message timestamp
 * Checks if message is within acceptable time window
 */
function validateTimestamp(messageTimestamp) {
  const now = Date.now();
  const msgTime = new Date(messageTimestamp).getTime();

  // Check if message is too old
  if (now - msgTime > MESSAGE_TIME_WINDOW_MS) {
    return {
      valid: false,
      reason: 'Message timestamp is too old (outside time window)'
    };
  }

  // Check if message is from the future (clock skew protection)
  if (msgTime - now > MAX_CLOCK_SKEW_MS) {
    return {
      valid: false,
      reason: 'Message timestamp is from the future (possible clock skew attack)'
    };
  }

  return { valid: true };
}

/**
 * Validate nonce uniqueness
 * Checks if nonce has been used before
 */
async function validateNonce(nonce) {
  try {
    const existingMessage = await Message.findOne({ nonce });

    if (existingMessage) {
      return {
        valid: false,
        reason: 'Nonce has already been used (replay attack detected)'
      };
    }

    return { valid: true };
  } catch (error) {
    console.error('Nonce validation error:', error);
    return {
      valid: false,
      reason: 'Failed to validate nonce'
    };
  }
}

/**
 * Validate message sequence number
 * Ensures sequence numbers are monotonically increasing
 */
async function validateSequenceNumber(senderId, receiverId, messageSequence) {
  try {
    // Get the latest message in this conversation
    const latestMessage = await Message.findOne({
      $or: [
        { senderId, receiverId },
        { senderId: receiverId, receiverId: senderId }
      ]
    })
    .sort({ messageSequence: -1 })
    .limit(1);

    if (!latestMessage) {
      // First message in conversation - any sequence number is valid
      return { valid: true };
    }

    // Sequence number must be greater than the last one
    if (messageSequence <= latestMessage.messageSequence) {
      return {
        valid: false,
        reason: `Invalid sequence number. Expected > ${latestMessage.messageSequence}, got ${messageSequence} (replay attack or out-of-order delivery)`
      };
    }

    // Check for suspicious gaps (possible message loss or attack)
    const gap = messageSequence - latestMessage.messageSequence;
    if (gap > 100) {
      console.warn(`Large sequence number gap detected: ${gap} messages`);
    }

    return { valid: true };
  } catch (error) {
    console.error('Sequence validation error:', error);
    return {
      valid: false,
      reason: 'Failed to validate sequence number'
    };
  }
}

/**
 * Get next sequence number for a conversation
 */
async function getNextSequenceNumber(senderId, receiverId) {
  try {
    const latestMessage = await Message.findOne({
      $or: [
        { senderId, receiverId },
        { senderId: receiverId, receiverId: senderId }
      ]
    })
    .sort({ messageSequence: -1 })
    .limit(1);

    return latestMessage ? latestMessage.messageSequence + 1 : 1;
  } catch (error) {
    console.error('Error getting next sequence number:', error);
    return 1;
  }
}

/**
 * Comprehensive replay attack protection validation
 * Validates all three mechanisms: nonce, timestamp, and sequence
 */
async function validateMessage(senderId, receiverId, nonce, timestamp, messageSequence) {
  const validationResults = {
    nonce: { valid: false },
    timestamp: { valid: false },
    sequence: { valid: false },
    overall: false,
    errors: []
  };

  // 1. Validate Nonce
  validationResults.nonce = await validateNonce(nonce);
  if (!validationResults.nonce.valid) {
    validationResults.errors.push(validationResults.nonce.reason);
  }

  // 2. Validate Timestamp
  validationResults.timestamp = validateTimestamp(timestamp);
  if (!validationResults.timestamp.valid) {
    validationResults.errors.push(validationResults.timestamp.reason);
  }

  // 3. Validate Sequence Number
  validationResults.sequence = await validateSequenceNumber(senderId, receiverId, messageSequence);
  if (!validationResults.sequence.valid) {
    validationResults.errors.push(validationResults.sequence.reason);
  }

  // Overall validation passes only if all three pass
  validationResults.overall =
    validationResults.nonce.valid &&
    validationResults.timestamp.valid &&
    validationResults.sequence.valid;

  return validationResults;
}

/**
 * Log replay attack attempt for security monitoring
 */
async function logReplayAttempt(senderId, receiverId, nonce, validationResults) {
  console.error('🚨 REPLAY ATTACK DETECTED 🚨');
  console.error({
    timestamp: new Date().toISOString(),
    senderId,
    receiverId,
    nonce,
    validationResults,
    severity: 'HIGH'
  });

  // In production, you would:
  // 1. Log to security monitoring system
  // 2. Increment attack counter for this user
  // 3. Potentially rate-limit or ban the attacker
  // 4. Send alert to security team
}

module.exports = {
  generateNonce,
  validateTimestamp,
  validateNonce,
  validateSequenceNumber,
  getNextSequenceNumber,
  validateMessage,
  logReplayAttempt,
  MESSAGE_TIME_WINDOW_MS,
  MAX_CLOCK_SKEW_MS
};
