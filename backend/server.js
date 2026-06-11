require('dotenv').config();
const express = require('express');
const http = require('http');
const cors = require('cors');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const connectDB = require('./config/database');
const authRoutes = require('./routes/authRoutes');
const keyRoutes = require('./routes/keyRoutes');
const keyExchangeRoutes = require('./routes/keyExchangeRoutes');
const messageRoutes = require('./routes/messageRoutes');
const userRoutes = require('./routes/userRoutes');
const fileRoutes = require('./routes/fileRoutes');
const Message = require('./models/Message');

const app = express();
const server = http.createServer(app);

connectDB();

const allowedOrigins = (process.env.CLIENT_URL || 'http://localhost:3000')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);

const corsOptions = {
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('Origin is not allowed by CORS'));
  },
  credentials: true
};

const io = new Server(server, {
  cors: corsOptions
});

app.use(cors(corsOptions));

// Increase payload size limit for encrypted files (50MB)
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

app.use('/api/auth', authRoutes);
app.use('/api/keys', keyRoutes);
app.use('/api/key-exchange', keyExchangeRoutes);
app.use('/api/messages', messageRoutes);
app.use('/api/users', userRoutes);
app.use('/api/files', fileRoutes);

app.get('/api/health', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Server is running'
  });
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    success: false,
    message: 'Something went wrong!',
    ...(process.env.NODE_ENV === 'development' && { error: err.message })
  });
});

// Socket.io authentication and real-time messaging
const connectedUsers = new Map(); // userId -> socketId

io.use((socket, next) => {
  const token = socket.handshake.auth.token;

  if (!token) {
    return next(new Error('Authentication error'));
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    socket.userId = decoded.id;
    next();
  } catch (error) {
    next(new Error('Authentication error'));
  }
});

io.on('connection', (socket) => {
  console.log(`User connected: ${socket.userId}`);

  // Store user's socket connection
  connectedUsers.set(socket.userId, socket.id);

  // Notify others that user is online
  socket.broadcast.emit('user-online', { userId: socket.userId });

  // Announce only messages that have already passed the authenticated REST flow.
  socket.on('message-saved', async ({ receiverId, messageId }) => {
    try {
      const message = await Message.findOne({
        _id: messageId,
        senderId: socket.userId,
        receiverId
      }).lean();

      if (!message) {
        return;
      }

      const receiverSocketId = connectedUsers.get(receiverId);
      if (receiverSocketId) {
        io.to(receiverSocketId).emit('receive-message', {
          _id: message._id,
          senderId: socket.userId,
          ciphertext: message.ciphertext,
          iv: message.iv,
          messageType: message.messageType,
          fileMetadata: message.fileMetadata,
          nonce: message.nonce,
          messageSequence: message.messageSequence,
          timestamp: message.timestamp
        });
      }
    } catch (error) {
      console.error('Message notification error:', error);
    }
  });

  // Handle key exchange initiated event
  socket.on('key-exchange-initiated', (data) => {
    const { receiverId, exchangeId } = data;
    const receiverSocketId = connectedUsers.get(receiverId);

    if (receiverSocketId) {
      io.to(receiverSocketId).emit('key-exchange-request', {
        senderId: socket.userId,
        exchangeId
      });
    }
  });

  // Handle key exchange response event
  socket.on('key-exchange-responded', (data) => {
    const { initiatorId } = data;
    const initiatorSocketId = connectedUsers.get(initiatorId);

    if (initiatorSocketId) {
      io.to(initiatorSocketId).emit('key-exchange-completed', {
        responderId: socket.userId
      });
    }
  });

  // Handle typing indicator
  socket.on('typing', (data) => {
    const { receiverId } = data;
    const receiverSocketId = connectedUsers.get(receiverId);

    if (receiverSocketId) {
      io.to(receiverSocketId).emit('user-typing', {
        userId: socket.userId
      });
    }
  });

  // Handle stop typing
  socket.on('stop-typing', (data) => {
    const { receiverId } = data;
    const receiverSocketId = connectedUsers.get(receiverId);

    if (receiverSocketId) {
      io.to(receiverSocketId).emit('user-stop-typing', {
        userId: socket.userId
      });
    }
  });

  // Handle disconnect
  socket.on('disconnect', () => {
    console.log(`User disconnected: ${socket.userId}`);
    connectedUsers.delete(socket.userId);

    // Notify others that user is offline
    socket.broadcast.emit('user-offline', { userId: socket.userId });
  });
});

const PORT = process.env.PORT || 5000;

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = { server, io };
