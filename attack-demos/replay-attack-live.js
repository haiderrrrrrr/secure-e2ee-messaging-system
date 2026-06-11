/**
 * Live Replay Attack Demonstration Against Running System
 * Requires: backend running at http://localhost:5000, users alice & bob
 */

const axios = require('axios');
const BASE_URL = process.env.API_URL || 'http://localhost:5000/api';

// Sanitize console output: remove emojis and non-ASCII
const __origLog = console.log;
const __origError = console.error;
function __sanitize(arg) {
  return typeof arg === 'string' ? arg.replace(/[^\x00-\x7F]/g, '') : arg;
}
console.log = (...args) => __origLog(...args.map(__sanitize));
console.error = (...args) => __origError(...args.map(__sanitize));

async function login(username, password) {
  const res = await axios.post(`${BASE_URL}/auth/login`, { username, password });
  return { token: res.data.token, user: res.data.user };
}

async function sendMessage(token, receiverUsername, payload) {
  const res = await axios.post(
    `${BASE_URL}/messages/send`,
    {
      receiverUsername,
      ciphertext: payload.ciphertext,
      iv: payload.iv,
      messageType: 'text',
      fileMetadata: null,
      nonce: payload.nonce,
      messageSequence: payload.messageSequence,
      timestamp: payload.timestamp
    },
    { headers: { Authorization: `Bearer ${token}` } }
  );
  return res.data;
}

function randHex(bytes = 12) {
  const buf = Buffer.alloc(bytes);
  for (let i = 0; i < bytes; i++) buf[i] = Math.floor(Math.random() * 256);
  return buf.toString('hex');
}

function buildPayload(text, { nonce, sequence, timestamp }) {
  // This demo uses placeholder ciphertext/iv; server stores without decrypting.
  // In real flow, ciphertext/iv come from client-side AES-GCM.
  return {
    ciphertext: Buffer.from(`PLAINTEXT:${text}`).toString('base64'),
    iv: Buffer.from(randHex(12)).toString('base64'),
    nonce,
    messageSequence: sequence,
    timestamp
  };
}

async function demo() {
  console.log('==============================================================================');
  console.log('LIVE REPLAY ATTACK DEMONSTRATION');
  console.log('==============================================================================');
  console.log();

  // Login as alice (sender)
  let alice;
  try {
    alice = await login('alice', 'password123');
    console.log(`Alice logged in (userId=${alice.user.id})`);
  } catch (e) {
    console.error('Login failed for alice:', e.message);
    console.log('Ensure backend is running and user alice exists with password123');
    process.exit(1);
  }

  // Prepare baseline metadata
  const baseNonce = `${Date.now()}_${randHex(16)}_${Math.floor(Math.random() * 1e9)}`;
  const baseTimestamp = new Date().toISOString();
  const baseSequence = 1000; // assume current conv seq baseline

  console.log('\nScenario 1: Duplicate Nonce (simple replay)');
  console.log('-------------------------------------------');
  const p1 = buildPayload('Hello Bob (original)', {
    nonce: baseNonce,
    sequence: baseSequence + 1,
    timestamp: baseTimestamp
  });
  const p1Replay = buildPayload('Hello Bob (replay attempt)', {
    nonce: baseNonce, // same nonce -> should be rejected
    sequence: baseSequence + 2,
    timestamp: baseTimestamp
  });

  try {
    const r1 = await sendMessage(alice.token, 'bob', p1);
    console.log('Original send accepted:', r1?.success ?? true);
  } catch (e) {
    console.error('Original send failed:', e.response?.data || e.message);
  }

  try {
    const r1r = await sendMessage(alice.token, 'bob', p1Replay);
    console.log('Replay (duplicate nonce) accepted:', r1r?.success ?? true);
  } catch (e) {
    console.log('Replay (duplicate nonce) rejected as expected:', e.response?.data || e.message);
  }

  console.log('\nScenario 2: Old Timestamp (delayed replay)');
  console.log('------------------------------------------');
  const oldTs = new Date(Date.now() - 10 * 60 * 1000).toISOString(); // 10 minutes ago
  const p2 = buildPayload('Old message replay', {
    nonce: `${Date.now()}_${randHex(16)}_${Math.floor(Math.random() * 1e9)}`,
    sequence: baseSequence + 3,
    timestamp: oldTs
  });
  try {
    const r2 = await sendMessage(alice.token, 'bob', p2);
    console.log('Old timestamp accepted (unexpected):', r2?.success ?? true);
  } catch (e) {
    console.log('Old timestamp rejected as expected:', e.response?.data || e.message);
  }

  console.log('\nScenario 3: Sequence Rollback (out-of-order)');
  console.log('--------------------------------------------');
  const p3a = buildPayload('Later message', {
    nonce: `${Date.now()}_${randHex(16)}_${Math.floor(Math.random() * 1e9)}`,
    sequence: baseSequence + 10,
    timestamp: new Date().toISOString()
  });
  const p3b = buildPayload('Replay old sequence', {
    nonce: `${Date.now()}_${randHex(16)}_${Math.floor(Math.random() * 1e9)}`,
    sequence: baseSequence + 5, // lower than latest -> should be rejected
    timestamp: new Date().toISOString()
  });

  try {
    const r3a = await sendMessage(alice.token, 'bob', p3a);
    console.log('Advancing sequence accepted:', r3a?.success ?? true);
  } catch (e) {
    console.error('Advancing sequence failed:', e.response?.data || e.message);
  }

  try {
    const r3b = await sendMessage(alice.token, 'bob', p3b);
    console.log('Sequence rollback accepted (unexpected):', r3b?.success ?? true);
  } catch (e) {
    console.log('Sequence rollback rejected as expected:', e.response?.data || e.message);
  }

  console.log('\nSummary');
  console.log('-------');
  console.log('Duplicate Nonce: should be rejected by DB unique constraint / server validation');
  console.log('Old Timestamp: should be rejected by time-window validation');
  console.log('Sequence Rollback: should be rejected by monotonic sequence rule');

  console.log('\nDone.');
}

demo().catch(err => {
  console.error('Fatal error:', err.message);
  process.exit(1);
});
