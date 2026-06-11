import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json'
  }
});

api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

export const authAPI = {
  register: async (username, password) => {
    const response = await api.post('/auth/register', { username, password });
    return response.data;
  },

  login: async (username, password) => {
    const response = await api.post('/auth/login', { username, password });
    return response.data;
  },

  verifyToken: async () => {
    const response = await api.get('/auth/verify');
    return response.data;
  },

  getMe: async () => {
    const response = await api.get('/auth/me');
    return response.data;
  }
};

export const keyAPI = {
  uploadPublicKey: async (publicKey, algorithm, keyFingerprint) => {
    const response = await api.post('/keys/upload', { publicKey, algorithm, keyFingerprint });
    return response.data;
  },

  getMyKeyInfo: async () => {
    const response = await api.get('/keys/my-info');
    return response.data;
  },

  getPublicKey: async (username) => {
    const response = await api.get(`/keys/${username}`);
    return response.data;
  }
};

export const keyExchangeAPI = {
  initiateExchange: async (peerUsername, exchangeData) => {
    const response = await api.post('/key-exchange/initiate', {
      peerUsername,
      exchangeData
    });
    return response.data;
  },

  respondToExchange: async (exchangeId, responseData) => {
    const response = await api.post('/key-exchange/respond', {
      exchangeId,
      responseData
    });
    return response.data;
  },

  finalizeExchange: async (exchangeId) => {
    const response = await api.get(`/key-exchange/${exchangeId}/finalize`);
    return response.data;
  },

  getPendingExchanges: async () => {
    const response = await api.get('/key-exchange/pending');
    return response.data;
  },

  getExchangeData: async (exchangeId) => {
    const response = await api.get(`/key-exchange/${exchangeId}/data`);
    return response.data;
  },

  getExchangeStatus: async (exchangeId) => {
    const response = await api.get(`/key-exchange/${exchangeId}/status`);
    return response.data;
  }
};

export const messageAPI = {
  sendMessage: async (receiverUsername, ciphertext, iv, messageType, fileMetadata, nonce, messageSequence, timestamp) => {
    const response = await api.post('/messages/send', {
      receiverUsername,
      ciphertext,
      iv,
      messageType,
      fileMetadata,
      nonce,
      messageSequence,
      timestamp
    });
    return response.data;
  },

  getConversation: async (username, limit = 50, before = null) => {
    const params = { limit };
    if (before) params.before = before;

    const response = await api.get(`/messages/conversation/${username}`, { params });
    return response.data;
  },

  markAsRead: async (username) => {
    const response = await api.put(`/messages/mark-read/${username}`);
    return response.data;
  },

  getConversations: async () => {
    const response = await api.get('/messages/conversations');
    return response.data;
  },

  deleteMessage: async (messageId) => {
    const response = await api.delete(`/messages/${messageId}`);
    return response.data;
  }
};

export const userAPI = {
  getAllUsers: async () => {
    const response = await api.get('/users');
    return response.data;
  },

  searchUsers: async (query) => {
    const response = await api.get('/users/search', { params: { q: query } });
    return response.data;
  },

  getUserByUsername: async (username) => {
    const response = await api.get(`/users/${username}`);
    return response.data;
  }
};

export const fileAPI = {
  uploadFile: async (receiverUsername, encryptedData, iv, fileName, fileType, fileSize) => {
    const response = await api.post('/files/upload', {
      receiverUsername,
      encryptedData,
      iv,
      fileName,
      fileType,
      fileSize
    });
    return response.data;
  },

  downloadFile: async (fileId) => {
    const response = await api.get(`/files/${fileId}`);
    return response.data;
  },

  getConversationFiles: async (username, limit = 50) => {
    const response = await api.get(`/files/conversation/${username}`, {
      params: { limit }
    });
    return response.data;
  },

  deleteFile: async (fileId) => {
    const response = await api.delete(`/files/${fileId}`);
    return response.data;
  }
};

export default api;
