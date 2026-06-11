import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { keyExchangeAPI, messageAPI, userAPI, fileAPI } from '../services/api';
import {
  initiateKeyExchange,
  finalizeKeyExchange,
  respondToKeyExchange,
  storeSessionKey,
  getSessionKey
} from '../utils/keyExchange';
import { encryptMessage, decryptMessage, encryptFile, decryptFile } from '../utils/encryption';
import {
  createMessageMetadata,
  loadSequencesFromStorage,
  saveSequencesToStorage,
  syncSequenceNumber
} from '../utils/replayProtection';
import socketService from '../services/socket';
import AppHeader from './AppHeader';
import './Chat.css';

const Chat = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [contacts, setContacts] = useState([]);
  const [selectedContact, setSelectedContact] = useState(null);
  const [messages, setMessages] = useState([]);
  const [messageText, setMessageText] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [keyExchangeStatus, setKeyExchangeStatus] = useState({});
  const [sessionKeys, setSessionKeys] = useState({});
  const [onlineUsers, setOnlineUsers] = useState(new Set());
  const [pendingKeyExchangeRequest, setPendingKeyExchangeRequest] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [showAddUserModal, setShowAddUserModal] = useState(false);
  const [allUsers, setAllUsers] = useState([]);
  const [myContacts, setMyContacts] = useState(new Set());
  const [uploadProgress, setUploadProgress] = useState(0);
  const [isUploading, setIsUploading] = useState(false);
  const messagesEndRef = useRef(null);
  const fileInputRef = useRef(null);
  const messageIdCounter = useRef(0);

  // Initialize socket connection and load replay protection state
  useEffect(() => {
    // Load sequence numbers from storage
    if (user?.id) {
      loadSequencesFromStorage(user.id);
    }

    const token = localStorage.getItem('token');
    if (token) {
      socketService.connect(token);

      // Listen for incoming messages
      socketService.onReceiveMessage(handleReceiveMessage);

      // Listen for key exchange requests
      socketService.onKeyExchangeRequest(handleKeyExchangeRequest);

      // Listen for key exchange completion
      socketService.onKeyExchangeCompleted(handleKeyExchangeCompleted);

      // Listen for user online/offline
      socketService.onUserOnline((data) => {
        setOnlineUsers(prev => new Set([...prev, data.userId]));
      });

      socketService.onUserOffline((data) => {
        setOnlineUsers(prev => {
          const newSet = new Set(prev);
          newSet.delete(data.userId);
          return newSet;
        });
      });
    }

    // Save sequence numbers periodically
    const saveInterval = setInterval(() => {
      if (user?.id) {
        saveSequencesToStorage(user.id);
      }
    }, 30000); // Save every 30 seconds

    return () => {
      socketService.disconnect();
      clearInterval(saveInterval);
      // Save one last time before unmounting
      if (user?.id) {
        saveSequencesToStorage(user.id);
      }
    };
    // Handler functions intentionally use the latest component state through React closures.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.id]);

  useEffect(() => {
    loadContacts();
    // Contacts are loaded once after the authenticated chat screen mounts.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  // Generate unique message ID
  const generateUniqueMessageId = () => {
    messageIdCounter.current += 1;
    return `${Date.now()}_${messageIdCounter.current}_${Math.random().toString(36).substr(2, 9)}`;
  };

  const loadContacts = async () => {
    try {
      // Load my contacts from localStorage
      const savedContacts = localStorage.getItem(`contacts_${user.id}`);
      if (savedContacts) {
        const contactIds = new Set(JSON.parse(savedContacts));
        setMyContacts(contactIds);

        // Load full user data for my contacts
        const response = await userAPI.getAllUsers();
        const myContactsList = response.data.filter(u => contactIds.has(u._id));
        setContacts(myContactsList);
      } else {
        setContacts([]);
        setMyContacts(new Set());
      }
    } catch (error) {
      console.error('Failed to load contacts:', error);
    }
  };

  const addUserToContacts = async (userId) => {
    const newContacts = new Set([...myContacts, userId]);
    setMyContacts(newContacts);
    localStorage.setItem(`contacts_${user.id}`, JSON.stringify([...newContacts]));
    await loadContacts();
  };

  const removeUserFromContacts = (userId) => {
    const newContacts = new Set(myContacts);
    newContacts.delete(userId);
    setMyContacts(newContacts);
    localStorage.setItem(`contacts_${user.id}`, JSON.stringify([...newContacts]));
    loadContacts();
  };

  const loadAllUsers = async () => {
    try {
      const response = await userAPI.getAllUsers();
      setAllUsers(response.data.filter(u => u._id !== user.id));
    } catch (error) {
      console.error('Failed to load users:', error);
    }
  };

  const selectContact = async (contact) => {
    setSelectedContact(contact);
    setLoading(true);

    try {
      // Check if session key exists
      const existingKey = await getSessionKey(contact._id);
      if (existingKey) {
        setSessionKeys(prev => ({ ...prev, [contact._id]: existingKey }));
        setKeyExchangeStatus(prev => ({ ...prev, [contact._id]: 'established' }));
      }

      // Load conversation history
      const conversationResponse = await messageAPI.getConversation(contact.username);
      const encryptedMessages = conversationResponse.data;

      // Sync sequence number from latest message
      if (encryptedMessages.length > 0) {
        const latestMessage = encryptedMessages[encryptedMessages.length - 1];
        if (latestMessage.messageSequence) {
          syncSequenceNumber(contact._id, latestMessage.messageSequence);
        }
      }

      // Decrypt messages if we have the session key
      if (existingKey) {
        const decryptedMessages = await Promise.all(
          encryptedMessages.map(async (msg) => {
            try {
              const plaintext = await decryptMessage(
                msg.ciphertext,
                msg.iv,
                existingKey
              );

              return {
                _id: msg._id,
                senderId: msg.senderId,
                receiverId: msg.receiverId,
                content: plaintext,
                messageType: msg.messageType,
                fileMetadata: msg.fileMetadata,
                timestamp: msg.timestamp,
                encrypted: true
              };
            } catch (error) {
              console.error('Failed to decrypt message:', error);
              return {
                _id: msg._id,
                senderId: msg.senderId,
                receiverId: msg.receiverId,
                content: '[Message encrypted with old key - perform new key exchange to read new messages]',
                messageType: msg.messageType,
                timestamp: msg.timestamp,
                encrypted: false,
                decryptionFailed: true
              };
            }
          })
        );

        setMessages(decryptedMessages);
      } else {
        // Show encrypted messages as unreadable
        setMessages(
          encryptedMessages.map(msg => ({
            _id: msg._id,
            senderId: msg.senderId,
            receiverId: msg.receiverId,
            content: '[Encrypted - Key exchange required]',
            messageType: msg.messageType,
            timestamp: msg.timestamp,
            encrypted: false
          }))
        );
      }

      // Mark messages as read
      await messageAPI.markAsRead(contact.username);
    } catch (error) {
      console.error('Failed to load conversation:', error);
      setMessages([]);
    } finally {
      setLoading(false);
    }
  };

  const handleSendMessage = async (e) => {
    e.preventDefault();

    if (!messageText.trim() && !selectedFile) return;
    if (!selectedContact) return;

    const sessionKey = sessionKeys[selectedContact._id];
    if (!sessionKey) {
      alert('Please complete key exchange before sending messages');
      return;
    }

    setLoading(true);

    try {
      // REPLAY ATTACK PROTECTION: Generate message metadata
      const replayProtection = createMessageMetadata(selectedContact._id);
      console.log('📝 Message metadata:', {
        nonce: replayProtection.nonce.substring(0, 20) + '...',
        sequence: replayProtection.messageSequence,
        timestamp: replayProtection.timestamp
      });

      let ciphertext, iv, messageType, fileMetadata = null;
      let response;

      if (selectedFile) {
        setIsUploading(true);
        setUploadProgress(0);

        // Simulate encryption progress
        setUploadProgress(20);

        // Encrypt file
        const encryptedFileData = await encryptFile(selectedFile, sessionKey);
        setUploadProgress(50);

        ciphertext = encryptedFileData.encryptedData;
        iv = encryptedFileData.iv;
        messageType = 'file';

        // Upload file via fileAPI first to get the file ID
        setUploadProgress(70);
        const fileUploadResponse = await fileAPI.uploadFile(
          selectedContact.username,
          ciphertext,
          iv,
          encryptedFileData.fileName,
          encryptedFileData.fileType,
          encryptedFileData.fileSize
        );
        setUploadProgress(100);

        // Store file ID in metadata for later download
        fileMetadata = {
          fileId: fileUploadResponse.data.fileId,
          fileName: encryptedFileData.fileName,
          fileType: encryptedFileData.fileType,
          fileSize: encryptedFileData.fileSize
        };

        // Small delay to show 100%
        await new Promise(resolve => setTimeout(resolve, 300));
        setIsUploading(false);
        setUploadProgress(0);

        // Send message with file metadata (including fileId) + replay protection
        response = await messageAPI.sendMessage(
          selectedContact.username,
          ciphertext,
          iv,
          messageType,
          fileMetadata,
          replayProtection.nonce,
          replayProtection.messageSequence,
          replayProtection.timestamp
        );
      } else {
        // Encrypt text message
        const encryptedMessage = await encryptMessage(messageText, sessionKey);
        ciphertext = encryptedMessage.ciphertext;
        iv = encryptedMessage.iv;
        messageType = 'text';

        // Send text message via messageAPI + replay protection
        response = await messageAPI.sendMessage(
          selectedContact.username,
          ciphertext,
          iv,
          messageType,
          fileMetadata,
          replayProtection.nonce,
          replayProtection.messageSequence,
          replayProtection.timestamp
        );
      }

      // Notify the recipient after the authenticated API has persisted the message.
      socketService.notifyMessageSaved(
        selectedContact._id,
        response.data._id
      );

      // Add to local messages with unique ID
      const newMessage = {
        _id: response.data._id || generateUniqueMessageId(),
        senderId: { _id: user.id, username: user.username },
        receiverId: { _id: selectedContact._id, username: selectedContact.username },
        content: selectedFile ? `File: ${selectedFile.name}` : messageText,
        messageType,
        fileMetadata,
        timestamp: new Date(),
        encrypted: true
      };

      setMessages(prev => {
        // Check if message already exists to prevent duplicates
        const exists = prev.some(msg => msg._id === newMessage._id);
        if (exists) return prev;
        return [...prev, newMessage];
      });

      setMessageText('');
      setSelectedFile(null);
      if (fileInputRef.current) fileInputRef.current.value = '';
    } catch (error) {
      console.error('Failed to send message:', error);
      alert('Failed to send message. Please try again.');
      setIsUploading(false);
      setUploadProgress(0);
    } finally {
      setLoading(false);
    }
  };

  const handleReceiveMessage = async (data) => {
    const { senderId, ciphertext, iv, messageType, fileMetadata, timestamp } = data;

    // Get the session key for this sender
    setSessionKeys(currentKeys => {
      const sessionKey = currentKeys[senderId];

      if (sessionKey) {
        // Decrypt and add message
        (async () => {
          try {
            let content;
            if (messageType === 'file') {
              content = `File: ${fileMetadata.fileName}`;
            } else {
              content = await decryptMessage(ciphertext, iv, sessionKey);
            }

            const newMessage = {
              _id: generateUniqueMessageId(),
              senderId: { _id: senderId },
              content,
              messageType,
              fileMetadata,
              timestamp,
              encrypted: true,
              ciphertext,
              iv
            };

            setMessages(prev => {
              // Check for duplicates based on content, timestamp, and sender
              const isDuplicate = prev.some(msg =>
                msg.content === content &&
                msg.senderId._id === senderId &&
                Math.abs(new Date(msg.timestamp) - new Date(timestamp)) < 1000 // Within 1 second
              );

              if (isDuplicate) {
                console.log('Duplicate message detected, skipping');
                return prev;
              }

              return [...prev, newMessage];
            });
          } catch (error) {
            console.error('Failed to decrypt received message:', error);
          }
        })();
      }

      return currentKeys; // Return unchanged keys
    });
  };

  const handleDownloadFile = async (fileId, fileName, fileType) => {
    if (!selectedContact) return;

    const sessionKey = sessionKeys[selectedContact._id];
    if (!sessionKey) {
      alert('Session key not available. Please perform key exchange again.');
      return;
    }

    try {
      // Fetch encrypted file from server
      const response = await fileAPI.downloadFile(fileId);
      const { encryptedData, iv } = response.data;

      // Decrypt file
      const decryptedBlob = await decryptFile(encryptedData, iv, sessionKey, fileName, fileType);

      // Create download link
      const url = window.URL.createObjectURL(decryptedBlob);
      const a = document.createElement('a');
      a.href = url;
      a.download = fileName;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

    } catch (error) {
      console.error('File download error:', error);
      alert('Failed to download file. Please try again.');
    }
  };

  const handleKeyExchange = async () => {
    if (!selectedContact) return;

    try {
      setKeyExchangeStatus(prev => ({ ...prev, [selectedContact._id]: 'initiating' }));

      console.log('Starting key exchange with user:', selectedContact.username);
      console.log('Current user ID:', user.id);

      // Step 1: Initiate key exchange
      console.log('Step 1: Initiating key exchange...');
      const { ephemeralKeyPair, exchangeData } = await initiateKeyExchange(user.id);
      console.log('Ephemeral key pair generated:', ephemeralKeyPair);
      console.log('Exchange data:', exchangeData);

      // Step 2: Send to server
      const response = await keyExchangeAPI.initiateExchange(
        selectedContact.username,
        exchangeData
      );

      const { exchangeId, peerPublicKey } = response.data;

      // Notify peer via Socket.io
      socketService.keyExchangeInitiated(selectedContact._id, exchangeId);

      setKeyExchangeStatus(prev => ({ ...prev, [selectedContact._id]: 'waiting' }));

      // Store exchange data for finalization
      window.pendingKeyExchange = {
        [selectedContact._id]: {
          ephemeralKeyPair,
          exchangeData,
          exchangeId,
          peerPublicKey
        }
      };

    } catch (error) {
      console.error('Key exchange error details:', error);
      console.error('Error message:', error.message);
      console.error('Error stack:', error.stack);
      if (error.response) {
        console.error('Server response:', error.response.data);
      }
      setKeyExchangeStatus(prev => ({ ...prev, [selectedContact._id]: 'failed' }));
      alert(error.response?.data?.message || error.message || 'Key exchange failed. Please try again.');
    }
  };

  const handleKeyExchangeRequest = async (data) => {
    const { senderId, exchangeId } = data;

    // Store the pending request to show UI
    const senderContact = contacts.find(c => c._id === senderId);
    setPendingKeyExchangeRequest({
      senderId,
      exchangeId,
      senderUsername: senderContact?.username || 'Unknown User',
      data
    });
  };

  const acceptKeyExchangeRequest = async () => {
    if (!pendingKeyExchangeRequest) return;

    const { senderId, exchangeId } = pendingKeyExchangeRequest;

    try {
      // Fetch the exchange data from the backend
      const exchangeDataResponse = await keyExchangeAPI.getExchangeData(exchangeId);
      const { initiatorExchangeData, initiatorPublicKey } = exchangeDataResponse.data;

      // Respond to key exchange
      const { sessionKey, responseData } = await respondToKeyExchange(
        user.id,
        initiatorPublicKey,
        initiatorExchangeData
      );

      // Send response to server
      await keyExchangeAPI.respondToExchange(exchangeId, responseData);

      // Notify initiator
      socketService.keyExchangeResponded(senderId);

      // Store session key
      storeSessionKey(senderId, sessionKey);
      setSessionKeys(prev => ({ ...prev, [senderId]: sessionKey }));
      setKeyExchangeStatus(prev => ({ ...prev, [senderId]: 'established' }));

      // Clear the pending request
      setPendingKeyExchangeRequest(null);

      alert('Key exchange completed!');
    } catch (error) {
      console.error('Key exchange response error:', error);
      setPendingKeyExchangeRequest(null);
      alert('Failed to complete key exchange');
    }
  };

  const rejectKeyExchangeRequest = () => {
    setPendingKeyExchangeRequest(null);
  };

  const handleKeyExchangeCompleted = async (data) => {
    const { responderId } = data;

    if (!window.pendingKeyExchange || !window.pendingKeyExchange[responderId]) {
      return;
    }

    try {
      const { ephemeralKeyPair, exchangeData, exchangeId, peerPublicKey } =
        window.pendingKeyExchange[responderId];

      // Finalize key exchange
      const finalizeResponse = await keyExchangeAPI.finalizeExchange(exchangeId);

      const sessionKey = await finalizeKeyExchange(
        ephemeralKeyPair,
        new Uint8Array(exchangeData.salt),
        peerPublicKey,
        finalizeResponse.data.responderExchangeData
      );

      // Store session key
      storeSessionKey(responderId, sessionKey);
      setSessionKeys(prev => ({ ...prev, [responderId]: sessionKey }));
      setKeyExchangeStatus(prev => ({ ...prev, [responderId]: 'established' }));

      alert('Secure key exchange completed! Messages will now be encrypted.');

      // Clean up
      delete window.pendingKeyExchange[responderId];
    } catch (error) {
      console.error('Key exchange finalization error:', error);
      alert('Failed to finalize key exchange');
    }
  };

  const handleFileSelect = (e) => {
    const file = e.target.files[0];
    if (file) {
      // Check file size limit (50MB)
      const maxSize = 50 * 1024 * 1024; // 50MB in bytes
      if (file.size > maxSize) {
        alert(`File size exceeds the maximum limit of 50MB. Your file is ${formatFileSize(file.size)}.`);
        if (fileInputRef.current) {
          fileInputRef.current.value = '';
        }
        return;
      }
      setSelectedFile(file);
    }
  };

  const removeFile = () => {
    setSelectedFile(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const formatFileSize = (bytes) => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  };

  const isContactOnline = (contactId) => {
    return onlineUsers.has(contactId);
  };

  const handleLogoutFromChat = () => {
    socketService.disconnect();
    logout();
    navigate('/login');
  };

  return (
    <div className="chat-container">
      <AppHeader showBack={true} onLogout={handleLogoutFromChat} />

      {/* Key Exchange Request Modal */}
      {pendingKeyExchangeRequest && (
        <div className="modal-overlay">
          <div className="modal-content">
            <h3>Key Exchange Request</h3>
            <p>
              <strong>{pendingKeyExchangeRequest.senderUsername}</strong> wants to establish
              a secure encrypted connection with you.
            </p>
            <p className="modal-info">
              This will generate a shared encryption key for secure messaging.
            </p>
            <div className="modal-actions">
              <button
                className="btn-accept"
                onClick={acceptKeyExchangeRequest}
              >
                Accept
              </button>
              <button
                className="btn-reject"
                onClick={rejectKeyExchangeRequest}
              >
                Reject
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="chat-content">
        {/* Sidebar - Contacts List */}
        <div className="chat-sidebar">
        <div className="sidebar-header">
          <h2>Chats</h2>
          <button
            className="btn-add-user"
            onClick={() => {
              setShowAddUserModal(true);
              loadAllUsers();
            }}
            title="Add User"
          >
            + Add User
          </button>
        </div>

        <div className="search-bar">
          <input
            type="text"
            placeholder="Search contacts..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="search-input"
          />
        </div>

        <div className="contacts-list">
          {contacts
            .filter(contact =>
              contact.username.toLowerCase().includes(searchQuery.toLowerCase())
            )
            .map((contact) => (
            <div
              key={contact._id}
              className={`contact-item ${selectedContact?._id === contact._id ? 'active' : ''}`}
              onClick={() => selectContact(contact)}
            >
              <div className="contact-avatar">
                {contact.username[0].toUpperCase()}
              </div>
              <div className="contact-info">
                <div className="contact-name">{contact.username}</div>
                <div className="contact-status">
                  {contact.publicKey ? (
                    <span className="key-badge">🔐 Secured</span>
                  ) : (
                    <span className="no-key-badge">⚠ No keys</span>
                  )}
                </div>
              </div>
              {isContactOnline(contact._id) && <span className="status-indicator online"></span>}
            </div>
          ))}
        </div>
      </div>

      {/* Main Chat Area */}
      <div className="chat-main">
        {selectedContact ? (
          <>
            {/* Chat Header */}
            <div className="chat-header">
              <div className="chat-user-info">
                <div className="contact-avatar">
                  {selectedContact.username[0].toUpperCase()}
                </div>
                <div>
                  <h3>{selectedContact.username}</h3>
                  <span className="chat-status">
                    {sessionKeys[selectedContact._id]
                      ? '🔒 End-to-End Encrypted'
                      : selectedContact.publicKey
                        ? '⚠ Not Encrypted - Key Exchange Required'
                        : '⚠ Peer has no keys'}
                  </span>
                </div>
              </div>
              <button
                className="btn-secondary"
                onClick={handleKeyExchange}
                disabled={
                  !selectedContact.publicKey ||
                  sessionKeys[selectedContact._id] ||
                  keyExchangeStatus[selectedContact._id] === 'initiating' ||
                  keyExchangeStatus[selectedContact._id] === 'waiting'
                }
              >
                {keyExchangeStatus[selectedContact._id] === 'initiating' && 'Initiating...'}
                {keyExchangeStatus[selectedContact._id] === 'waiting' && 'Waiting for peer...'}
                {keyExchangeStatus[selectedContact._id] === 'established' && 'Key Established'}
                {(!keyExchangeStatus[selectedContact._id] ||
                  keyExchangeStatus[selectedContact._id] === 'failed' ||
                  keyExchangeStatus[selectedContact._id] === 'timeout') && 'Start Key Exchange'}
              </button>
            </div>

            {/* Messages Area */}
            <div className="messages-area">
              {/* Show warning if there are decryption failures */}
              {messages.some(msg => msg.decryptionFailed) && (
                <div className="decryption-warning">
                  <p>⚠️ Some messages couldn't be decrypted (encrypted with old session key)</p>
                  <p>Perform a new key exchange to decrypt future messages. Old messages cannot be recovered.</p>
                </div>
              )}

              {loading && messages.length === 0 ? (
                <div className="no-messages">
                  <p>Loading messages...</p>
                </div>
              ) : messages.length === 0 ? (
                <div className="no-messages">
                  <p>No messages yet. Start a secure conversation!</p>
                  {!selectedContact.publicKey ? (
                    <p className="warning">⚠ This user hasn't generated encryption keys yet</p>
                  ) : !sessionKeys[selectedContact._id] ? (
                    <p className="warning">⚠ Click "Start Key Exchange" to establish encryption</p>
                  ) : null}
                </div>
              ) : (
                messages.map((msg) => (
                  <div
                    key={msg._id}
                    className={`message ${msg.senderId?._id === user.id || msg.senderId === user.id ? 'sent' : 'received'}`}
                  >
                    <div className="message-bubble">
                      {msg.messageType === 'text' ? (
                        <p>{msg.content}</p>
                      ) : (
                        <div className="file-message">
                          <div className="file-icon">📎</div>
                          <div className="file-info">
                            <div className="file-name">{msg.fileMetadata?.fileName}</div>
                            <div className="file-size">{formatFileSize(msg.fileMetadata?.fileSize)}</div>
                          </div>
                          <button
                            className="btn-download"
                            onClick={() => handleDownloadFile(msg.fileMetadata?.fileId, msg.fileMetadata?.fileName, msg.fileMetadata?.fileType)}
                            title="Download file"
                            disabled={!msg.fileMetadata?.fileId}
                          >
                            ⬇
                          </button>
                        </div>
                      )}
                      <div className="message-meta">
                        <span className="message-time">
                          {new Date(msg.timestamp).toLocaleTimeString()}
                        </span>
                        {msg.encrypted && <span className="encrypted-badge">🔒</span>}
                      </div>
                    </div>
                  </div>
                ))
              )}
              <div ref={messagesEndRef} />
            </div>

            {/* Message Input */}
            <div className="message-input-area">
              {selectedFile && (
                <div className="file-preview">
                  <div className="file-preview-content">
                    <span className="file-icon">📎</span>
                    <span className="file-name">{selectedFile.name}</span>
                    <span className="file-size">({formatFileSize(selectedFile.size)})</span>
                    <button className="btn-remove-file" onClick={removeFile}>×</button>
                  </div>
                  {isUploading && (
                    <div className="upload-progress-container">
                      <div className="upload-progress-bar" style={{ width: `${uploadProgress}%` }}>
                        <span className="upload-progress-text">{uploadProgress}%</span>
                      </div>
                    </div>
                  )}
                </div>
              )}

              <form onSubmit={handleSendMessage} className="message-form">
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={handleFileSelect}
                  style={{ display: 'none' }}
                />
                <button
                  type="button"
                  className="btn-attach"
                  onClick={() => fileInputRef.current?.click()}
                  title="Attach file"
                  disabled={!sessionKeys[selectedContact._id]}
                >
                  📎
                </button>

                <input
                  type="text"
                  className="message-input"
                  placeholder={
                    sessionKeys[selectedContact._id]
                      ? 'Type a message...'
                      : 'Complete key exchange to send messages'
                  }
                  value={messageText}
                  onChange={(e) => setMessageText(e.target.value)}
                  disabled={loading || !sessionKeys[selectedContact._id]}
                />

                <button
                  type="submit"
                  className="btn-send"
                  disabled={loading || isUploading || (!messageText.trim() && !selectedFile) || !sessionKeys[selectedContact._id]}
                >
                  {isUploading ? `${uploadProgress}%` : loading ? '⏳' : '➤'}
                </button>
              </form>
            </div>
          </>
        ) : (
          <div className="no-chat-selected">
            <div className="empty-state">
              <h2>Welcome to Secure Chat</h2>
              <p>Select a contact to start a secure, encrypted conversation</p>
              <div className="features">
                <div className="feature">🔒 End-to-End Encryption</div>
                <div className="feature">📁 Secure File Sharing</div>
                <div className="feature">🔑 Key Exchange Protocol</div>
              </div>
            </div>
          </div>
        )}
      </div>
      </div>

      {/* Add User Modal */}
      {showAddUserModal && (
        <div className="modal-overlay" onClick={() => setShowAddUserModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Add User to Contacts</h2>
              <button className="modal-close" onClick={() => setShowAddUserModal(false)}>
                ×
              </button>
            </div>
            <div className="modal-body">
              <div className="users-list">
                {allUsers.length === 0 ? (
                  <p className="no-users">No users available to add</p>
                ) : (
                  allUsers.map((userItem) => (
                    <div key={userItem._id} className="user-item">
                      <div className="user-avatar">
                        {userItem.username[0].toUpperCase()}
                      </div>
                      <div className="user-info">
                        <div className="user-name">{userItem.username}</div>
                        <div className="user-status">
                          {userItem.publicKey ? (
                            <span className="key-badge-small">🔐 Has keys</span>
                          ) : (
                            <span className="no-key-badge-small">⚠ No keys</span>
                          )}
                        </div>
                      </div>
                      {myContacts.has(userItem._id) ? (
                        <button
                          className="btn-remove"
                          onClick={() => removeUserFromContacts(userItem._id)}
                        >
                          Remove
                        </button>
                      ) : (
                        <button
                          className="btn-add"
                          onClick={() => {
                            addUserToContacts(userItem._id);
                            setShowAddUserModal(false);
                          }}
                        >
                          Add
                        </button>
                      )}
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Chat;
