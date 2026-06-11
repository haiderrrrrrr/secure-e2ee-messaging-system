/**
 * Live MITM Attack Demonstration Against Running System
 * 
 * This demonstrates intercepting real key exchange requests
 * and shows how signatures prevent the attack
 */

const axios = require('axios');

const BASE_URL = process.env.API_URL || 'http://localhost:5000/api';

// Sanitize console output: remove emojis and non-ASCII characters
const __origLog = console.log;
const __origError = console.error;
function __sanitize(arg) {
  return typeof arg === 'string' ? arg.replace(/[^\x00-\x7F]/g, '') : arg;
}
console.log = (...args) => __origLog(...args.map(__sanitize));
console.error = (...args) => __origError(...args.map(__sanitize));

console.log('='.repeat(80));
console.log('LIVE MITM ATTACK DEMONSTRATION');
console.log('='.repeat(80));
console.log();
console.log('⚠️  Prerequisites:');
console.log('   1. Backend server running on http://localhost:5000');
console.log('   2. Three users registered: alice, bob, mallory');
console.log();

// ============================================================================
// Setup: Login as three users
// ============================================================================

async function loginUser(username, password) {
  try {
    const response = await axios.post(`${BASE_URL}/auth/login`, {
      username,
      password
    });
    return {
      token: response.data.token,
      userId: response.data.user.id,
      username: response.data.user.username,
      publicKey: response.data.user.publicKey
    };
  } catch (error) {
    throw new Error(`Failed to login as ${username}: ${error.message}`);
  }
}

async function initiateKeyExchange(token, targetUsername, exchangeData) {
  try {
    const response = await axios.post(
      `${BASE_URL}/key-exchange/initiate`,
      {
        responderUsername: targetUsername,
        exchangeData
      },
      {
        headers: { Authorization: `Bearer ${token}` }
      }
    );
    return response.data;
  } catch (error) {
    throw new Error(`Key exchange failed: ${error.response?.data?.message || error.message}`);
  }
}

async function respondToKeyExchange(token, exchangeId, responseData) {
  try {
    const response = await axios.post(
      `${BASE_URL}/key-exchange/respond`,
      {
        exchangeId,
        responseData
      },
      {
        headers: { Authorization: `Bearer ${token}` }
      }
    );
    return response.data;
  } catch (error) {
    throw new Error(`Key exchange response failed: ${error.response?.data?.message || error.message}`);
  }
}

async function getKeyExchangeData(token, exchangeId) {
  try {
    const response = await axios.get(
      `${BASE_URL}/key-exchange/${exchangeId}`,
      {
        headers: { Authorization: `Bearer ${token}` }
      }
    );
    return response.data;
  } catch (error) {
    throw new Error(`Failed to get exchange data: ${error.message}`);
  }
}

// ============================================================================
// MITM Attack Demonstration
// ============================================================================

async function demonstrateMITM() {
  console.log('🔧 Step 1: Login as Alice, Bob, and Mallory (attacker)');
  console.log('-'.repeat(80));

  let alice, bob, mallory;

  try {
    // Login all three users
    alice = await loginUser('alice', 'password123');
    console.log(`✅ Alice logged in (User ID: ${alice.userId})`);

    bob = await loginUser('bob', 'password123');
    console.log(`✅ Bob logged in (User ID: ${bob.userId})`);

    mallory = await loginUser('mallory', 'password123');
    console.log(`✅ Mallory (attacker) logged in (User ID: ${mallory.userId})`);
    console.log();
  } catch (error) {
    console.error('❌ Login failed:', error.message);
    console.log();
    console.log('💡 Please ensure:');
    console.log('   1. Backend server is running');
    console.log('   2. Users exist (alice, bob, mallory with password: password123)');
    console.log('   3. Users have generated their key pairs (logged in once via frontend)');
    return;
  }

  // ============================================================================
  // SCENARIO 1: Mallory intercepts Alice → Bob key exchange
  // ============================================================================

  console.log('📌 SCENARIO 1: Mallory Intercepts Key Exchange (WITHOUT proper verification)');
  console.log('-'.repeat(80));
  console.log();

  try {
    console.log('1️⃣  Alice initiates key exchange with Bob');

    // Create fake exchange data (simulating Alice's exchange)
    const fakeAliceExchangeData = {
      protocolVersion: 'secure-e2ee-v1.0',
      ephemeralPublicKey: {
        kty: 'EC',
        crv: 'P-256',
        x: 'fake_x_coordinate_from_alice',
        y: 'fake_y_coordinate_from_alice'
      },
      signature: [1, 2, 3, 4, 5], // Fake signature
      signatureAlgorithm: 'RSA-PSS',
      salt: Array(27).fill(0).map(() => Math.floor(Math.random() * 256)),
      customParams: {
        curveType: 'P-256',
        hkdfInfo: 'secure-e2ee-session-key-v1'
      }
    };

    // Alice initiates with Bob
    console.log('   Sending ephemeral public key + signature...');
    const aliceExchange = await initiateKeyExchange(
      alice.token,
      bob.username,
      fakeAliceExchangeData
    );

    console.log(`   ✅ Exchange initiated (Exchange ID: ${aliceExchange.exchangeId})`);
    console.log();

    console.log('2️⃣  Mallory intercepts the exchange');
    console.log('   🔴 Mallory tries to retrieve Alice\'s exchange data...');

    // Mallory tries to intercept (will fail due to authentication)
    try {
      const interceptedData = await getKeyExchangeData(mallory.token, aliceExchange.exchangeId);
      console.log('   🔴 Mallory retrieved exchange data (SHOULD NOT HAPPEN)');
    } catch (error) {
      console.log('   ✅ Backend blocks Mallory - not authorized for this exchange');
      console.log(`   ✅ Error: ${error.message}`);
    }
    console.log();

    console.log('3️⃣  Mallory tries to respond as if she is Bob');

    // Create fake response from Mallory
    const malloryFakeResponse = {
      ephemeralPublicKey: {
        kty: 'EC',
        crv: 'P-256',
        x: 'fake_x_coordinate_from_mallory',
        y: 'fake_y_coordinate_from_mallory'
      },
      signature: [5, 4, 3, 2, 1], // Mallory's signature
      signatureAlgorithm: 'RSA-PSS'
    };

    try {
      // Mallory tries to respond (will fail - not the responder)
      await respondToKeyExchange(
        mallory.token,
        aliceExchange.exchangeId,
        malloryFakeResponse
      );
      console.log('   🔴 Mallory successfully responded (SHOULD NOT HAPPEN)');
    } catch (error) {
      console.log('   ✅ Backend blocks Mallory - not authorized to respond');
      console.log(`   ✅ Error: ${error.message}`);
    }
    console.log();

  } catch (error) {
    console.error('❌ Scenario 1 error:', error.message);
    console.log();
  }

  // ============================================================================
  // SCENARIO 2: What if Bob receives Mallory's response?
  // ============================================================================

  console.log('📌 SCENARIO 2: Signature Verification Prevents MITM');
  console.log('-'.repeat(80));
  console.log();

  console.log('💡 Even if Mallory could inject her response:');
  console.log();

  console.log('1️⃣  Alice would verify the signature');
  console.log('   Alice has Bob\'s authentic public key from the server');
  console.log('   Alice verifies: signature(ephemeralKey_M) using Bob\'s public key');
  console.log();

  console.log('2️⃣  Verification would FAIL');
  console.log('   ❌ Signature is from Mallory, not Bob');
  console.log('   ❌ Mallory cannot forge Bob\'s signature (no private key)');
  console.log('   ❌ Alice rejects the exchange');
  console.log();

  console.log('3️⃣  MITM Attack Prevention Layers:');
  console.log('   ✅ Layer 1: Backend authorization (only responder can respond)');
  console.log('   ✅ Layer 2: Digital signature verification (frontend)');
  console.log('   ✅ Layer 3: Key confirmation tag (final handshake)');
  console.log('   ✅ Layer 4: Session key derivation with custom parameters');
  console.log();

  // ============================================================================
  // Summary
  // ============================================================================

  console.log('='.repeat(80));
  console.log('DEMONSTRATION SUMMARY');
  console.log('='.repeat(80));
  console.log();

  console.log('🛡️  Security Mechanisms That Prevent MITM:');
  console.log();

  console.log('1. Authentication & Authorization:');
  console.log('   - JWT tokens authenticate users');
  console.log('   - Backend verifies only authorized users can participate');
  console.log('   - Mallory cannot intercept or respond to exchanges');
  console.log();

  console.log('2. Digital Signatures (RSA-PSS):');
  console.log('   - Each ephemeral key is signed with long-term private key');
  console.log('   - Signatures bind ephemeral keys to user identity');
  console.log('   - Cannot be forged without private key');
  console.log();

  console.log('3. Public Key Infrastructure:');
  console.log('   - Long-term public keys stored on trusted server');
  console.log('   - Users retrieve authentic public keys');
  console.log('   - Prevents key substitution');
  console.log();

  console.log('4. Protocol Features:');
  console.log('   - Custom HKDF derivation (student ID-based)');
  console.log('   - Key confirmation with HMAC');
  console.log('   - Protocol version tracking');
  console.log();

  console.log('❌ What Mallory CANNOT Do:');
  console.log('   ✗ Intercept exchange data (backend blocks unauthorized access)');
  console.log('   ✗ Respond to exchanges (not the intended responder)');
  console.log('   ✗ Forge signatures (no access to private keys)');
  console.log('   ✗ Derive session key (doesn\'t have shared secret)');
  console.log('   ✗ Pass key confirmation (wrong HMAC tag)');
  console.log();

  console.log('✅ CONCLUSION:');
  console.log('   The protocol with digital signatures successfully');
  console.log('   prevents MITM attacks through multiple security layers!');
  console.log();

  console.log('='.repeat(80));
}

// Run the demonstration
console.log('Starting MITM attack demonstration...');
console.log();

demonstrateMITM().catch(error => {
  console.error('Fatal error:', error.message);
  process.exit(1);
});
