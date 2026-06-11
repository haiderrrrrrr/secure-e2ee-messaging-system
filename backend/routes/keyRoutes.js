const express = require('express');
const router = express.Router();
const { uploadPublicKey, getPublicKey, getMyKeyInfo } = require('../controllers/keyController');
const { protect } = require('../middleware/auth');

router.post('/upload', protect, uploadPublicKey);
router.get('/my-info', protect, getMyKeyInfo);
router.get('/:username', protect, getPublicKey);

module.exports = router;
