const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/auth');
const fileController = require('../controllers/fileController');

// All routes require authentication
router.use(protect);

// Upload encrypted file
router.post('/upload', fileController.uploadFile);

// Download encrypted file
router.get('/:fileId', fileController.downloadFile);

// Get files for a conversation
router.get('/conversation/:username', fileController.getConversationFiles);

// Delete file
router.delete('/:fileId', fileController.deleteFile);

module.exports = router;
