const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/auth');
const messageController = require('../controllers/messageController');

// All routes require authentication
router.use(protect);

// Send message
router.post('/send', messageController.sendMessage);

// Get conversation with a user
router.get('/conversation/:username', messageController.getConversation);

// Mark messages as read
router.put('/mark-read/:username', messageController.markMessagesAsRead);

// Get all conversations
router.get('/conversations', messageController.getConversations);

// Delete message
router.delete('/:messageId', messageController.deleteMessage);

module.exports = router;
