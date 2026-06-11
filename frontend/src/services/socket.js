import { io } from 'socket.io-client';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';
const SOCKET_URL = process.env.REACT_APP_SOCKET_URL || API_URL.replace(/\/api\/?$/, '');

class SocketService {
  constructor() {
    this.socket = null;
    this.connected = false;
  }

  connect(token) {
    if (this.socket?.connected) {
      return this.socket;
    }

    this.socket = io(SOCKET_URL, {
      auth: {
        token
      },
      autoConnect: true
    });

    this.socket.on('connect', () => {
      console.log('Socket connected');
      this.connected = true;
    });

    this.socket.on('disconnect', () => {
      console.log('Socket disconnected');
      this.connected = false;
    });

    this.socket.on('connect_error', (error) => {
      console.error('Socket connection error:', error);
      this.connected = false;
    });

    return this.socket;
  }

  disconnect() {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
      this.connected = false;
    }
  }

  notifyMessageSaved(receiverId, messageId) {
    if (this.socket && this.connected) {
      this.socket.emit('message-saved', {
        receiverId,
        messageId
      });
    }
  }

  // Listen for incoming messages
  onReceiveMessage(callback) {
    if (this.socket) {
      this.socket.on('receive-message', callback);
    }
  }

  // Send key exchange initiated event
  keyExchangeInitiated(receiverId, exchangeId) {
    if (this.socket && this.connected) {
      this.socket.emit('key-exchange-initiated', {
        receiverId,
        exchangeId
      });
    }
  }

  // Listen for key exchange requests
  onKeyExchangeRequest(callback) {
    if (this.socket) {
      this.socket.on('key-exchange-request', callback);
    }
  }

  // Send key exchange response
  keyExchangeResponded(initiatorId) {
    if (this.socket && this.connected) {
      this.socket.emit('key-exchange-responded', {
        initiatorId
      });
    }
  }

  // Listen for key exchange completion
  onKeyExchangeCompleted(callback) {
    if (this.socket) {
      this.socket.on('key-exchange-completed', callback);
    }
  }

  // Typing indicator
  sendTyping(receiverId) {
    if (this.socket && this.connected) {
      this.socket.emit('typing', { receiverId });
    }
  }

  stopTyping(receiverId) {
    if (this.socket && this.connected) {
      this.socket.emit('stop-typing', { receiverId });
    }
  }

  onUserTyping(callback) {
    if (this.socket) {
      this.socket.on('user-typing', callback);
    }
  }

  onUserStopTyping(callback) {
    if (this.socket) {
      this.socket.on('user-stop-typing', callback);
    }
  }

  // Online/offline status
  onUserOnline(callback) {
    if (this.socket) {
      this.socket.on('user-online', callback);
    }
  }

  onUserOffline(callback) {
    if (this.socket) {
      this.socket.on('user-offline', callback);
    }
  }

  // Remove event listeners
  off(event, callback) {
    if (this.socket) {
      this.socket.off(event, callback);
    }
  }
}

const socketService = new SocketService();
export default socketService;
