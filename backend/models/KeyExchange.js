const mongoose = require('mongoose');

/**
 * Key Exchange Session Model
 * Tracks ECDH key exchange sessions between users
 */
const keyExchangeSchema = new mongoose.Schema({
  initiatorId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  responderId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  status: {
    type: String,
    enum: ['initiated', 'responded', 'completed', 'failed'],
    default: 'initiated'
  },
  initiatorExchangeData: {
    type: Object,
    required: true
  },
  responderExchangeData: {
    type: Object,
    required: false,
    default: null
  },
  expiresAt: {
    type: Date,
    required: true,
    default: () => new Date(Date.now() + 5 * 60 * 1000) // 5 minutes
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Index for efficient lookups
keyExchangeSchema.index({ initiatorId: 1, responderId: 1 });
keyExchangeSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // TTL index

module.exports = mongoose.model('KeyExchange', keyExchangeSchema);
