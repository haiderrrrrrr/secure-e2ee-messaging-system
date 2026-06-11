const Message = require('../models/Message');
const User = require('../models/User');
const {
  validateMessage,
  getNextSequenceNumber,
  logReplayAttempt
} = require('../utils/replayProtection');
const {
  logMessageAccess,
  logUnauthorizedAccess,
  logReplayAttack,
  logDuplicateNonce,
  logInvalidTimestamp,
  logInvalidSequence
} = require('../utils/securityLogger');

/**
 * Send an encrypted message with Replay Attack Protection
 * POST /api/messages/send
 *
 * Required replay protection fields:
 * - nonce: Cryptographically random unique identifier
 * - messageSequence: Monotonically increasing sequence number
 * - timestamp: Message creation timestamp
 */
exports.sendMessage = async (req, res) => {
  try {
    const { receiverUsername, ciphertext, iv, messageType, fileMetadata, nonce, messageSequence, timestamp } = req.body;

    // Validate required fields including replay protection
    if (!receiverUsername || !ciphertext || !iv || !nonce || !messageSequence || !timestamp) {
      return res.status(400).json({
        success: false,
        message: 'Receiver username, ciphertext, IV, nonce, messageSequence, and timestamp are required'
      });
    }

    // Find receiver
    const receiver = await User.findOne({ username: receiverUsername });

    if (!receiver) {
      return res.status(404).json({
        success: false,
        message: 'Receiver not found'
      });
    }

    // REPLAY ATTACK PROTECTION: Validate message
    const validationResults = await validateMessage(
      req.user.id,
      receiver._id,
      nonce,
      timestamp,
      messageSequence
    );

    if (!validationResults.overall) {
      // Log the replay attack attempt
      await logReplayAttempt(req.user.id, receiver._id, nonce, validationResults);
      
      // Log specific replay attack details to security logger
      if (!validationResults.nonce.valid) {
        logDuplicateNonce(nonce, req.user.id, receiver._id.toString());
      }
      if (!validationResults.timestamp.valid) {
        logInvalidTimestamp(
          timestamp,
          req.user.id,
          receiver._id.toString(),
          validationResults.timestamp.reason
        );
      }
      if (!validationResults.sequence.valid) {
        logInvalidSequence(
          'expected_from_db',
          messageSequence,
          req.user.id,
          receiver._id.toString()
        );
      }
      
      logReplayAttack('MESSAGE_REPLAY', {
        senderId: req.user.id,
        receiverId: receiver._id.toString(),
        nonce: nonce.substring(0, 20) + '...',
        errors: validationResults.errors
      });

      return res.status(403).json({
        success: false,
        message: 'Replay attack detected',
        errors: validationResults.errors,
        validationDetails: {
          nonceValid: validationResults.nonce.valid,
          timestampValid: validationResults.timestamp.valid,
          sequenceValid: validationResults.sequence.valid
        }
      });
    }

    // Create message (only encrypted data is stored)
    const message = new Message({
      senderId: req.user.id,
      receiverId: receiver._id,
      ciphertext,
      iv,
      messageType: messageType || 'text',
      fileMetadata: fileMetadata || null,
      nonce,
      messageSequence,
      timestamp: new Date(timestamp)
    });

    await message.save();

    // Populate sender info for response
    await message.populate('senderId', 'username');

    res.status(201).json({
      success: true,
      message: 'Message sent',
      data: message
    });

  } catch (error) {
    console.error('Send message error:', error);

    // Check if it's a duplicate nonce error (MongoDB unique constraint)
    if (error.code === 11000 && error.keyPattern && error.keyPattern.nonce) {
      return res.status(403).json({
        success: false,
        message: 'Replay attack detected: Nonce already used'
      });
    }

    res.status(500).json({
      success: false,
      message: 'Failed to send message'
    });
  }
};

/**
 * Get conversation between two users
 * GET /api/messages/conversation/:username
 */
exports.getConversation = async (req, res) => {
  try {
    const { username } = req.params;
    const { limit = 50, before } = req.query;

    // Find the other user
    const otherUser = await User.findOne({ username });

    if (!otherUser) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Build query
    const query = {
      $or: [
        { senderId: req.user.id, receiverId: otherUser._id },
        { senderId: otherUser._id, receiverId: req.user.id }
      ]
    };

    // Add timestamp filter if 'before' is provided (for pagination)
    if (before) {
      query.timestamp = { $lt: new Date(before) };
    }

    // Get messages
    const messages = await Message.find(query)
      .sort({ timestamp: -1 })
      .limit(parseInt(limit))
      .populate('senderId', 'username')
      .populate('receiverId', 'username');

    // Reverse to show oldest first
    messages.reverse();

    // Mark received messages as delivered
    await Message.updateMany(
      {
        senderId: otherUser._id,
        receiverId: req.user.id,
        delivered: false
      },
      { delivered: true }
    );

    res.status(200).json({
      success: true,
      data: messages
    });

  } catch (error) {
    console.error('Get conversation error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get conversation'
    });
  }
};

/**
 * Mark messages as read
 * PUT /api/messages/mark-read/:username
 */
exports.markMessagesAsRead = async (req, res) => {
  try {
    const { username } = req.params;

    const sender = await User.findOne({ username });

    if (!sender) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    await Message.updateMany(
      {
        senderId: sender._id,
        receiverId: req.user.id,
        read: false
      },
      { read: true }
    );

    res.status(200).json({
      success: true,
      message: 'Messages marked as read'
    });

  } catch (error) {
    console.error('Mark messages as read error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to mark messages as read'
    });
  }
};

/**
 * Get all conversations (list of users with latest message)
 * GET /api/messages/conversations
 */
exports.getConversations = async (req, res) => {
  try {
    // Get all messages involving current user
    const messages = await Message.aggregate([
      {
        $match: {
          $or: [
            { senderId: req.user._id },
            { receiverId: req.user._id }
          ]
        }
      },
      {
        $sort: { timestamp: -1 }
      },
      {
        $group: {
          _id: {
            $cond: [
              { $eq: ['$senderId', req.user._id] },
              '$receiverId',
              '$senderId'
            ]
          },
          lastMessage: { $first: '$$ROOT' },
          unreadCount: {
            $sum: {
              $cond: [
                {
                  $and: [
                    { $eq: ['$receiverId', req.user._id] },
                    { $eq: ['$read', false] }
                  ]
                },
                1,
                0
              ]
            }
          }
        }
      },
      {
        $sort: { 'lastMessage.timestamp': -1 }
      }
    ]);

    // Populate user info
    await User.populate(messages, {
      path: '_id',
      select: 'username publicKey algorithm'
    });

    await User.populate(messages, {
      path: 'lastMessage.senderId',
      select: 'username'
    });

    res.status(200).json({
      success: true,
      data: messages
    });

  } catch (error) {
    console.error('Get conversations error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get conversations'
    });
  }
};

/**
 * Delete a message (only sender can delete)
 * DELETE /api/messages/:messageId
 */
exports.deleteMessage = async (req, res) => {
  try {
    const { messageId } = req.params;

    const message = await Message.findById(messageId);

    if (!message) {
      return res.status(404).json({
        success: false,
        message: 'Message not found'
      });
    }

    // Only sender can delete
    if (message.senderId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Unauthorized to delete this message'
      });
    }

    await message.deleteOne();

    res.status(200).json({
      success: true,
      message: 'Message deleted'
    });

  } catch (error) {
    console.error('Delete message error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete message'
    });
  }
};
