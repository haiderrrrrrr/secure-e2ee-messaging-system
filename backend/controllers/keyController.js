const User = require('../models/User');

exports.uploadPublicKey = async (req, res) => {
  try {
    const { publicKey, algorithm, keyFingerprint } = req.body;
    const userId = req.user._id;

    if (!publicKey || !algorithm) {
      return res.status(400).json({
        success: false,
        message: 'Public key and algorithm are required'
      });
    }

    const validAlgorithms = ['RSA_2048', 'RSA_3072', 'ECC_P256', 'ECC_P384'];
    if (!validAlgorithms.includes(algorithm)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid algorithm'
      });
    }

    const user = await User.findById(userId);
    user.publicKey = publicKey;
    user.algorithm = algorithm;
    user.keyFingerprint = keyFingerprint;
    await user.save();

    console.log(`Public key uploaded for user: ${user.username}`);

    res.status(200).json({
      success: true,
      message: 'Public key uploaded successfully'
    });
  } catch (error) {
    console.error('Public key upload error:', error);
    res.status(500).json({
      success: false,
      message: 'Error uploading public key'
    });
  }
};

exports.getPublicKey = async (req, res) => {
  try {
    const { username } = req.params;

    const user = await User.findOne({ username }).select('username publicKey algorithm keyFingerprint');

    if (!user || !user.publicKey) {
      return res.status(404).json({
        success: false,
        message: 'Public key not found'
      });
    }

    res.status(200).json({
      success: true,
      data: {
        username: user.username,
        publicKey: user.publicKey,
        algorithm: user.algorithm,
        keyFingerprint: user.keyFingerprint
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error retrieving public key'
    });
  }
};

exports.getMyKeyInfo = async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('algorithm keyFingerprint');

    res.status(200).json({
      success: true,
      data: {
        hasPublicKey: !!user.algorithm,
        algorithm: user.algorithm || null,
        keyFingerprint: user.keyFingerprint || null
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error retrieving key info'
    });
  }
};
