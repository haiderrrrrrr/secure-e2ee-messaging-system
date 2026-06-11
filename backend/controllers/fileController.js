const File = require('../models/File');
const User = require('../models/User');
const {
  logFileUpload,
  logFileDownload,
  logUnauthorizedAccess
} = require('../utils/securityLogger');

/**
 * Upload encrypted file
 * POST /api/files/upload
 */
exports.uploadFile = async (req, res) => {
  try {
    const { receiverUsername, encryptedData, iv, fileName, fileType, fileSize } = req.body;

    if (!receiverUsername || !encryptedData || !iv || !fileName || !fileType || !fileSize) {
      return res.status(400).json({
        success: false,
        message: 'All file fields are required'
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

    // Create file record
    const file = new File({
      senderId: req.user.id,
      receiverId: receiver._id,
      encryptedData,
      iv,
      fileName,
      fileType,
      fileSize
    });

    await file.save();

    // Log file upload
    logFileUpload(
      req.user.id,
      file._id.toString(),
      fileName,
      fileSize,
      receiver._id.toString()
    );

    res.status(201).json({
      success: true,
      message: 'File uploaded successfully',
      data: {
        fileId: file._id,
        fileName: file.fileName,
        fileType: file.fileType,
        fileSize: file.fileSize,
        createdAt: file.createdAt
      }
    });

  } catch (error) {
    console.error('File upload error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to upload file'
    });
  }
};

/**
 * Download encrypted file
 * GET /api/files/:fileId
 */
exports.downloadFile = async (req, res) => {
  try {
    const { fileId } = req.params;

    const file = await File.findById(fileId);

    if (!file) {
      return res.status(404).json({
        success: false,
        message: 'File not found'
      });
    }

    // Verify user is sender or receiver
    if (file.senderId.toString() !== req.user.id &&
        file.receiverId.toString() !== req.user.id) {
      logUnauthorizedAccess(
        req.user.id,
        'file',
        'download',
        'User is not sender or receiver of this file'
      );
      return res.status(403).json({
        success: false,
        message: 'Unauthorized to access this file'
      });
    }

    // Log file download
    logFileDownload(req.user.id, fileId, file.fileName);

    res.status(200).json({
      success: true,
      data: {
        encryptedData: file.encryptedData,
        iv: file.iv,
        fileName: file.fileName,
        fileType: file.fileType,
        fileSize: file.fileSize,
        createdAt: file.createdAt
      }
    });

  } catch (error) {
    console.error('File download error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to download file'
    });
  }
};

/**
 * Get files for a conversation
 * GET /api/files/conversation/:username
 */
exports.getConversationFiles = async (req, res) => {
  try {
    const { username } = req.params;
    const limit = parseInt(req.query.limit) || 50;

    // Find the other user
    const otherUser = await User.findOne({ username });

    if (!otherUser) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Get files between these two users
    const files = await File.find({
      $or: [
        { senderId: req.user.id, receiverId: otherUser._id },
        { senderId: otherUser._id, receiverId: req.user.id }
      ]
    })
    .sort({ createdAt: -1 })
    .limit(limit)
    .select('-encryptedData'); // Don't send encrypted data in list view

    res.status(200).json({
      success: true,
      data: files
    });

  } catch (error) {
    console.error('Get conversation files error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get files'
    });
  }
};

/**
 * Delete file
 * DELETE /api/files/:fileId
 */
exports.deleteFile = async (req, res) => {
  try {
    const { fileId } = req.params;

    const file = await File.findById(fileId);

    if (!file) {
      return res.status(404).json({
        success: false,
        message: 'File not found'
      });
    }

    // Only sender can delete
    if (file.senderId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Only sender can delete files'
      });
    }

    await File.findByIdAndDelete(fileId);

    res.status(200).json({
      success: true,
      message: 'File deleted successfully'
    });

  } catch (error) {
    console.error('Delete file error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete file'
    });
  }
};
