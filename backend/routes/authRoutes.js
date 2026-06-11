const express = require('express');
const router = express.Router();
const { register, login, verifyToken } = require('../controllers/authController');
const { protect } = require('../middleware/auth');

router.post('/register', register);
router.post('/login', login);
router.get('/verify', verifyToken);
router.get('/me', protect, (req, res) => {
  res.status(200).json({
    success: true,
    user: req.user
  });
});

module.exports = router;
