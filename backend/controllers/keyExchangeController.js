const KeyExchange = require('../models/KeyExchange');
const User = require('../models/User');
const {
  logKeyExchangeInitiate,
  logKeyExchangeRespond,
  logKeyExchangeComplete,
  logKeyExchangeFailure,
  logUnauthorizedAccess
} = require('../utils/securityLogger');

/**
 * Initiate key exchange with a peer
 * POST /api/key-exchange/initiate
 */
exports.initiateKeyExchange = async (req, res) => {
  try {
    const { peerUsername, exchangeData } = req.body;

    if (!peerUsername || !exchangeData) {
      return res.status(400).json({
        success: false,
        message: 'Peer username and exchange data are required'
      });
    }

    // Find peer user
    const peer = await User.findOne({ username: peerUsername });

    if (!peer) {
      return res.status(404).json({
        success: false,
        message: 'Peer user not found'
      });
    }

    // Check if peer has public key
    if (!peer.publicKey) {
      return res.status(400).json({
        success: false,
        message: 'Peer has not generated encryption keys yet'
      });
    }

    // Delete any existing pending exchange between these users
    await KeyExchange.deleteMany({
      $or: [
        { initiatorId: req.user.id, responderId: peer._id },
        { initiatorId: peer._id, responderId: req.user.id }
      ],
      status: { $in: ['initiated', 'responded'] }
    });

    // Create new key exchange session
    const keyExchange = new KeyExchange({
      initiatorId: req.user.id,
      responderId: peer._id,
      status: 'initiated',
      initiatorExchangeData: exchangeData
    });

    await keyExchange.save();

    // Log key exchange initiation
    logKeyExchangeInitiate(
      keyExchange._id.toString(),
      req.user.id,
      peer._id.toString()
    );

    res.status(201).json({
      success: true,
      message: 'Key exchange initiated',
      data: {
        exchangeId: keyExchange._id,
        peerPublicKey: peer.publicKey
      }
    });

  } catch (error) {
    console.error('Key exchange initiation error:', error);
    logKeyExchangeFailure(
      'unknown',
      'Initiation failed',
      { error: error.message, initiatorId: req.user.id }
    );
    res.status(500).json({
      success: false,
      message: 'Failed to initiate key exchange'
    });
  }
};

/**
 * Respond to key exchange request
 * POST /api/key-exchange/respond
 */
exports.respondToKeyExchange = async (req, res) => {
  try {
    const { exchangeId, responseData } = req.body;

    if (!exchangeId || !responseData) {
      return res.status(400).json({
        success: false,
        message: 'Exchange ID and response data are required'
      });
    }

    // Find the key exchange session
    const keyExchange = await KeyExchange.findById(exchangeId);

    if (!keyExchange) {
      return res.status(404).json({
        success: false,
        message: 'Key exchange session not found or expired'
      });
    }

    // Verify user is the responder
    if (keyExchange.responderId.toString() !== req.user.id) {
      logUnauthorizedAccess(
        req.user.id,
        'key-exchange',
        'respond',
        'User is not the designated responder'
      );
      return res.status(403).json({
        success: false,
        message: 'Unauthorized to respond to this key exchange'
      });
    }

    // Check if already responded
    if (keyExchange.status !== 'initiated') {
      return res.status(400).json({
        success: false,
        message: 'Key exchange already processed'
      });
    }

    // Update key exchange with response
    keyExchange.responderExchangeData = responseData;
    keyExchange.status = 'responded';
    await keyExchange.save();

    // Log key exchange response
    logKeyExchangeRespond(exchangeId, req.user.id);

    // Get initiator's public key
    const initiator = await User.findById(keyExchange.initiatorId);

    res.status(200).json({
      success: true,
      message: 'Key exchange response sent',
      data: {
        initiatorPublicKey: initiator.publicKey
      }
    });

  } catch (error) {
    console.error('Key exchange response error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to respond to key exchange'
    });
  }
};

/**
 * Finalize key exchange (initiator gets responder's data)
 * GET /api/key-exchange/:exchangeId/finalize
 */
exports.finalizeKeyExchange = async (req, res) => {
  try {
    const { exchangeId } = req.params;

    const keyExchange = await KeyExchange.findById(exchangeId);

    if (!keyExchange) {
      return res.status(404).json({
        success: false,
        message: 'Key exchange session not found or expired'
      });
    }

    // Verify user is the initiator
    if (keyExchange.initiatorId.toString() !== req.user.id) {
      logUnauthorizedAccess(
        req.user.id,
        'key-exchange',
        'finalize',
        'User is not the initiator'
      );
      return res.status(403).json({
        success: false,
        message: 'Unauthorized to finalize this key exchange'
      });
    }

    // Check if responder has responded
    if (keyExchange.status !== 'responded') {
      return res.status(400).json({
        success: false,
        message: 'Waiting for peer to respond',
        status: keyExchange.status
      });
    }

    // Mark as completed
    keyExchange.status = 'completed';
    await keyExchange.save();

    // Log key exchange completion
    logKeyExchangeComplete(
      exchangeId,
      keyExchange.initiatorId.toString(),
      keyExchange.responderId.toString()
    );

    res.status(200).json({
      success: true,
      message: 'Key exchange completed',
      data: {
        responderExchangeData: keyExchange.responderExchangeData
      }
    });

  } catch (error) {
    console.error('Key exchange finalization error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to finalize key exchange'
    });
  }
};

/**
 * Get pending key exchange requests for current user
 * GET /api/key-exchange/pending
 */
exports.getPendingExchanges = async (req, res) => {
  try {
    const pendingExchanges = await KeyExchange.find({
      responderId: req.user.id,
      status: 'initiated'
    })
    .populate('initiatorId', 'username')
    .sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      data: pendingExchanges
    });

  } catch (error) {
    console.error('Get pending exchanges error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get pending exchanges'
    });
  }
};

/**
 * Get key exchange data for responder
 * GET /api/key-exchange/:exchangeId/data
 */
exports.getExchangeData = async (req, res) => {
  try {
    const { exchangeId } = req.params;

    const keyExchange = await KeyExchange.findById(exchangeId)
      .populate('initiatorId', 'username publicKey');

    if (!keyExchange) {
      return res.status(404).json({
        success: false,
        message: 'Key exchange session not found'
      });
    }

    // Verify user is the responder
    if (keyExchange.responderId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Unauthorized'
      });
    }

    res.status(200).json({
      success: true,
      data: {
        initiatorExchangeData: keyExchange.initiatorExchangeData,
        initiatorPublicKey: keyExchange.initiatorId.publicKey,
        initiatorUsername: keyExchange.initiatorId.username
      }
    });

  } catch (error) {
    console.error('Get exchange data error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get exchange data'
    });
  }
};

/**
 * Check key exchange status
 * GET /api/key-exchange/:exchangeId/status
 */
exports.getExchangeStatus = async (req, res) => {
  try {
    const { exchangeId } = req.params;

    const keyExchange = await KeyExchange.findById(exchangeId);

    if (!keyExchange) {
      return res.status(404).json({
        success: false,
        message: 'Key exchange session not found'
      });
    }

    // Verify user is part of this exchange
    if (keyExchange.initiatorId.toString() !== req.user.id &&
        keyExchange.responderId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Unauthorized'
      });
    }

    res.status(200).json({
      success: true,
      data: {
        status: keyExchange.status,
        createdAt: keyExchange.createdAt,
        expiresAt: keyExchange.expiresAt
      }
    });

  } catch (error) {
    console.error('Get exchange status error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get exchange status'
    });
  }
};
