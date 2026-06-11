const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/auth');
const keyExchangeController = require('../controllers/keyExchangeController');

// All routes require authentication
router.use(protect);

// Initiate key exchange
router.post('/initiate', keyExchangeController.initiateKeyExchange);

// Respond to key exchange
router.post('/respond', keyExchangeController.respondToKeyExchange);

// Finalize key exchange
router.get('/:exchangeId/finalize', keyExchangeController.finalizeKeyExchange);

// Get pending exchanges
router.get('/pending', keyExchangeController.getPendingExchanges);

// Get exchange data
router.get('/:exchangeId/data', keyExchangeController.getExchangeData);

// Get exchange status
router.get('/:exchangeId/status', keyExchangeController.getExchangeStatus);

module.exports = router;
