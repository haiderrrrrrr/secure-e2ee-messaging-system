const mongoose = require('mongoose');

/**
 * Message Model - Stores ONLY encrypted message data
 * NO PLAINTEXT is ever stored on the server
 */
const messageSchema = new mongoose.Schema({
  senderId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  receiverId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  // Encrypted message content (ciphertext + auth tag)
  ciphertext: {
    type: String,
    required: true
  },
  // Initialization Vector (12 bytes for AES-GCM)
  iv: {
    type: String,
    required: true
  },
  // Message type: 'text' or 'file'
  messageType: {
    type: String,
    enum: ['text', 'file'],
    default: 'text'
  },
  // For file messages - encrypted file metadata
  fileMetadata: {
    fileId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'File'
    },
    fileName: String,
    fileType: String,
    fileSize: Number
  },
  // Replay Attack Protection Fields
  nonce: {
    type: String,
    required: true,
    unique: true // Ensures nonces are never reused
  },
  messageSequence: {
    type: Number,
    required: true,
    index: true
  },
  // Timestamp
  timestamp: {
    type: Date,
    default: Date.now,
    index: true,
    required: true
  },
  // Message delivery status
  delivered: {
    type: Boolean,
    default: false
  },
  // Message read status
  read: {
    type: Boolean,
    default: false
  }
}, {
  timestamps: true
});

// Compound index for efficient conversation queries
messageSchema.index({ senderId: 1, receiverId: 1, timestamp: -1 });
messageSchema.index({ receiverId: 1, senderId: 1, timestamp: -1 });

// Index for unread messages
messageSchema.index({ receiverId: 1, read: 1 });

// Replay attack protection indexes
messageSchema.index({ senderId: 1, receiverId: 1, messageSequence: 1 });

module.exports = mongoose.model('Message', messageSchema);
