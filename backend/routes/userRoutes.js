const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/auth');
const userController = require('../controllers/userController');

// All routes require authentication
router.use(protect);

// Get all users
router.get('/', userController.getAllUsers);

// Search users
router.get('/search', userController.searchUsers);

// Get user by username
router.get('/:username', userController.getUserByUsername);

module.exports = router;
