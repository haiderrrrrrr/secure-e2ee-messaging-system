const User = require('../models/User');

/**
 * Get all users (excluding current user)
 * GET /api/users
 */
exports.getAllUsers = async (req, res) => {
  try {
    const users = await User.find(
      { _id: { $ne: req.user.id } },
      'username publicKey algorithm keyFingerprint createdAt'
    ).sort({ username: 1 });

    res.status(200).json({
      success: true,
      data: users
    });

  } catch (error) {
    console.error('Get all users error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get users'
    });
  }
};

/**
 * Search users by username
 * GET /api/users/search?q=username
 */
exports.searchUsers = async (req, res) => {
  try {
    const { q } = req.query;

    if (!q) {
      return res.status(400).json({
        success: false,
        message: 'Search query is required'
      });
    }

    const users = await User.find(
      {
        _id: { $ne: req.user.id },
        username: { $regex: q, $options: 'i' }
      },
      'username publicKey algorithm keyFingerprint'
    ).limit(10);

    res.status(200).json({
      success: true,
      data: users
    });

  } catch (error) {
    console.error('Search users error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to search users'
    });
  }
};

/**
 * Get user by username
 * GET /api/users/:username
 */
exports.getUserByUsername = async (req, res) => {
  try {
    const { username } = req.params;

    const user = await User.findOne(
      { username },
      'username publicKey algorithm keyFingerprint createdAt'
    );

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.status(200).json({
      success: true,
      data: user
    });

  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get user'
    });
  }
};
