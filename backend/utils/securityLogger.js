/**
 * Security logging and auditing utilities.
 */

const fs = require('fs');
const path = require('path');

// Log directory
const LOG_DIR = path.join(__dirname, '../logs');

// Ensure log directory exists
if (!fs.existsSync(LOG_DIR)) {
  fs.mkdirSync(LOG_DIR, { recursive: true });
}

// Log file paths
const LOG_FILES = {
  authentication: path.join(LOG_DIR, 'authentication.log'),
  keyExchange: path.join(LOG_DIR, 'key-exchange.log'),
  decryption: path.join(LOG_DIR, 'decryption-failures.log'),
  replayAttacks: path.join(LOG_DIR, 'replay-attacks.log'),
  signatures: path.join(LOG_DIR, 'signature-failures.log'),
  serverAccess: path.join(LOG_DIR, 'server-access.log'),
  security: path.join(LOG_DIR, 'security-events.log')
};

/**
 * Format log entry with timestamp and metadata
 */
function formatLogEntry(event, data) {
  const timestamp = new Date().toISOString();
  return JSON.stringify({
    timestamp,
    event,
    ...data,
    severity: data.severity || 'INFO'
  }) + '\n';
}

/**
 * Write log entry to file
 */
function writeLog(logFile, entry) {
  try {
    fs.appendFileSync(logFile, entry, 'utf8');
  } catch (error) {
    console.error(`Failed to write to log file ${logFile}:`, error);
  }
}

/**
 * Write to console and file
 */
function log(logFile, event, data) {
  const entry = formatLogEntry(event, data);
  
  // Write to file
  writeLog(logFile, entry);
  
  // Also write to general security log
  if (logFile !== LOG_FILES.security) {
    writeLog(LOG_FILES.security, entry);
  }
  
  // Console output for development
  if (process.env.NODE_ENV !== 'production') {
    const severity = data.severity || 'INFO';
    const icon = {
      'INFO': 'ℹ️',
      'WARN': '⚠️',
      'ERROR': '❌',
      'CRITICAL': '🚨'
    }[severity] || 'ℹ️';
    
    console.log(`${icon} [${severity}] ${event}:`, data);
  }
}

// ============================================================================
// Authentication Logging
// ============================================================================

/**
 * Log successful login
 */
function logLoginSuccess(userId, username, ipAddress) {
  log(LOG_FILES.authentication, 'LOGIN_SUCCESS', {
    userId,
    username,
    ipAddress,
    severity: 'INFO'
  });
}

/**
 * Log failed login attempt
 */
function logLoginFailure(username, reason, ipAddress) {
  log(LOG_FILES.authentication, 'LOGIN_FAILURE', {
    username,
    reason,
    ipAddress,
    severity: 'WARN'
  });
}

/**
 * Log user registration
 */
function logRegistration(userId, username, ipAddress) {
  log(LOG_FILES.authentication, 'REGISTRATION', {
    userId,
    username,
    ipAddress,
    severity: 'INFO'
  });
}

/**
 * Log logout
 */
function logLogout(userId, username) {
  log(LOG_FILES.authentication, 'LOGOUT', {
    userId,
    username,
    severity: 'INFO'
  });
}

// ============================================================================
// Key Exchange Logging
// ============================================================================

/**
 * Log key exchange initiation
 */
function logKeyExchangeInitiate(exchangeId, initiatorId, responderId) {
  log(LOG_FILES.keyExchange, 'KEY_EXCHANGE_INITIATED', {
    exchangeId,
    initiatorId,
    responderId,
    severity: 'INFO'
  });
}

/**
 * Log key exchange response
 */
function logKeyExchangeRespond(exchangeId, responderId) {
  log(LOG_FILES.keyExchange, 'KEY_EXCHANGE_RESPONDED', {
    exchangeId,
    responderId,
    severity: 'INFO'
  });
}

/**
 * Log key exchange completion
 */
function logKeyExchangeComplete(exchangeId, initiatorId, responderId) {
  log(LOG_FILES.keyExchange, 'KEY_EXCHANGE_COMPLETED', {
    exchangeId,
    initiatorId,
    responderId,
    severity: 'INFO'
  });
}

/**
 * Log key exchange failure
 */
function logKeyExchangeFailure(exchangeId, reason, details) {
  log(LOG_FILES.keyExchange, 'KEY_EXCHANGE_FAILURE', {
    exchangeId,
    reason,
    details,
    severity: 'ERROR'
  });
}

// ============================================================================
// Decryption Failure Logging
// ============================================================================

/**
 * Log failed message decryption attempt
 */
function logDecryptionFailure(messageId, userId, reason) {
  log(LOG_FILES.decryption, 'DECRYPTION_FAILURE', {
    messageId,
    userId,
    reason,
    severity: 'WARN'
  });
}

/**
 * Log authentication tag verification failure
 */
function logAuthTagFailure(messageId, senderId, receiverId) {
  log(LOG_FILES.decryption, 'AUTH_TAG_VERIFICATION_FAILED', {
    messageId,
    senderId,
    receiverId,
    reason: 'Message integrity compromised or wrong key',
    severity: 'ERROR'
  });
}

// ============================================================================
// Replay Attack Logging
// ============================================================================

/**
 * Log detected replay attack
 */
function logReplayAttack(attackType, details) {
  log(LOG_FILES.replayAttacks, 'REPLAY_ATTACK_DETECTED', {
    attackType,
    ...details,
    severity: 'CRITICAL'
  });
}

/**
 * Log duplicate nonce detection
 */
function logDuplicateNonce(nonce, senderId, receiverId) {
  log(LOG_FILES.replayAttacks, 'DUPLICATE_NONCE_DETECTED', {
    nonce: nonce.substring(0, 20) + '...',
    senderId,
    receiverId,
    reason: 'Nonce already used - possible replay attack',
    severity: 'CRITICAL'
  });
}

/**
 * Log invalid timestamp detection
 */
function logInvalidTimestamp(timestamp, senderId, receiverId, reason) {
  log(LOG_FILES.replayAttacks, 'INVALID_TIMESTAMP_DETECTED', {
    timestamp,
    senderId,
    receiverId,
    reason,
    severity: 'CRITICAL'
  });
}

/**
 * Log invalid sequence number
 */
function logInvalidSequence(expected, received, senderId, receiverId) {
  log(LOG_FILES.replayAttacks, 'INVALID_SEQUENCE_DETECTED', {
    expectedSequence: expected,
    receivedSequence: received,
    senderId,
    receiverId,
    reason: 'Out-of-order or replayed message',
    severity: 'CRITICAL'
  });
}

// ============================================================================
// Signature Verification Logging
// ============================================================================

/**
 * Log signature verification failure
 */
function logSignatureFailure(context, userId, reason) {
  log(LOG_FILES.signatures, 'SIGNATURE_VERIFICATION_FAILED', {
    context,
    userId,
    reason,
    severity: 'CRITICAL'
  });
}

/**
 * Log invalid signature format
 */
function logInvalidSignatureFormat(userId, details) {
  log(LOG_FILES.signatures, 'INVALID_SIGNATURE_FORMAT', {
    userId,
    details,
    severity: 'ERROR'
  });
}

// ============================================================================
// Server Access Logging
// ============================================================================

/**
 * Log message retrieval
 */
function logMessageAccess(userId, messageId, conversationWith) {
  log(LOG_FILES.serverAccess, 'MESSAGE_ACCESS', {
    userId,
    messageId,
    conversationWith,
    severity: 'INFO'
  });
}

/**
 * Log file upload
 */
function logFileUpload(userId, fileId, fileName, fileSize, receiverId) {
  log(LOG_FILES.serverAccess, 'FILE_UPLOAD', {
    userId,
    fileId,
    fileName,
    fileSize,
    receiverId,
    severity: 'INFO'
  });
}

/**
 * Log file download
 */
function logFileDownload(userId, fileId, fileName) {
  log(LOG_FILES.serverAccess, 'FILE_DOWNLOAD', {
    userId,
    fileId,
    fileName,
    severity: 'INFO'
  });
}

/**
 * Log unauthorized access attempt
 */
function logUnauthorizedAccess(userId, resource, action, reason) {
  log(LOG_FILES.serverAccess, 'UNAUTHORIZED_ACCESS_ATTEMPT', {
    userId,
    resource,
    action,
    reason,
    severity: 'CRITICAL'
  });
}

/**
 * Log metadata access
 */
function logMetadataAccess(userId, resource, action) {
  log(LOG_FILES.serverAccess, 'METADATA_ACCESS', {
    userId,
    resource,
    action,
    severity: 'INFO'
  });
}

// ============================================================================
// General Security Events
// ============================================================================

/**
 * Log general security event
 */
function logSecurityEvent(event, data) {
  log(LOG_FILES.security, event, {
    ...data,
    severity: data.severity || 'INFO'
  });
}

/**
 * Log suspicious activity
 */
function logSuspiciousActivity(userId, activity, details) {
  log(LOG_FILES.security, 'SUSPICIOUS_ACTIVITY', {
    userId,
    activity,
    details,
    severity: 'WARN'
  });
}

// ============================================================================
// Log Analysis Functions
// ============================================================================

/**
 * Read recent log entries
 */
function getRecentLogs(logType, limit = 100) {
  const logFile = LOG_FILES[logType];
  
  if (!logFile || !fs.existsSync(logFile)) {
    return [];
  }
  
  try {
    const content = fs.readFileSync(logFile, 'utf8');
    const lines = content.trim().split('\n');
    const recentLines = lines.slice(-limit);
    
    return recentLines.map(line => {
      try {
        return JSON.parse(line);
      } catch {
        return null;
      }
    }).filter(entry => entry !== null);
  } catch (error) {
    console.error(`Failed to read log file ${logFile}:`, error);
    return [];
  }
}

/**
 * Count events by type
 */
function getEventCounts(logType, timeWindow = 3600000) { // 1 hour default
  const logs = getRecentLogs(logType, 10000);
  const cutoffTime = Date.now() - timeWindow;
  
  const counts = {};
  
  logs.forEach(entry => {
    const entryTime = new Date(entry.timestamp).getTime();
    if (entryTime >= cutoffTime) {
      counts[entry.event] = (counts[entry.event] || 0) + 1;
    }
  });
  
  return counts;
}

/**
 * Get security summary
 */
function getSecuritySummary(timeWindow = 3600000) {
  return {
    authentication: getEventCounts('authentication', timeWindow),
    keyExchange: getEventCounts('keyExchange', timeWindow),
    decryption: getEventCounts('decryption', timeWindow),
    replayAttacks: getEventCounts('replayAttacks', timeWindow),
    signatures: getEventCounts('signatures', timeWindow),
    serverAccess: getEventCounts('serverAccess', timeWindow)
  };
}

// ============================================================================
// Exports
// ============================================================================

module.exports = {
  // Authentication
  logLoginSuccess,
  logLoginFailure,
  logRegistration,
  logLogout,
  
  // Key Exchange
  logKeyExchangeInitiate,
  logKeyExchangeRespond,
  logKeyExchangeComplete,
  logKeyExchangeFailure,
  
  // Decryption
  logDecryptionFailure,
  logAuthTagFailure,
  
  // Replay Attacks
  logReplayAttack,
  logDuplicateNonce,
  logInvalidTimestamp,
  logInvalidSequence,
  
  // Signatures
  logSignatureFailure,
  logInvalidSignatureFormat,
  
  // Server Access
  logMessageAccess,
  logFileUpload,
  logFileDownload,
  logUnauthorizedAccess,
  logMetadataAccess,
  
  // General
  logSecurityEvent,
  logSuspiciousActivity,
  
  // Analysis
  getRecentLogs,
  getEventCounts,
  getSecuritySummary,
  
  // Log file paths (for testing/monitoring)
  LOG_FILES
};
