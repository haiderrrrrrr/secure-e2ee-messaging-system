# Secure E2EE Messaging System

A full-stack encrypted messaging application with browser-side cryptography, authenticated key exchange, realtime delivery, encrypted file sharing, and replay protection.

## Live App

https://secure-e2ee-messaging-system.vercel.app

Backend health: [Render API](https://secure-e2ee-messaging-system-api.onrender.com/api/health)

## Features

- Account registration and JWT-based authentication
- RSA identity key generation with the Web Crypto API
- Browser-local private-key storage in IndexedDB
- Signed ephemeral ECDH P-256 key exchange
- HKDF-SHA-256 session-key derivation
- AES-256-GCM encryption for messages and files
- Authenticated realtime notifications with Socket.IO
- Nonce, timestamp, and sequence validation against replayed messages
- Encrypted conversation history stored in MongoDB
- Message delivery, read status, typing indicators, and contact management
- Structured server-side security event logs

## Security Flow

1. Each user generates an RSA identity key pair in the browser.
2. The public key is uploaded to the server; the private JWK remains in the browser's IndexedDB storage.
3. Two users establish a session through signed ephemeral ECDH P-256 keys.
4. Both clients derive the same AES-256-GCM session key with HKDF-SHA-256.
5. Messages and files are encrypted before they leave the browser.
6. The API validates message nonce, timestamp, and sequence values before storing ciphertext.
7. Socket.IO announces only messages that have already passed the authenticated API flow.

The server stores account metadata, public keys, encrypted payloads, initialization vectors, and delivery metadata. It does not receive message plaintext or private identity keys.

## Technology Stack

| Layer | Technologies |
| --- | --- |
| Frontend | React, React Router, Axios, Socket.IO Client, Web Crypto API, IndexedDB |
| Backend | Node.js, Express, Socket.IO, JWT, bcryptjs |
| Database | MongoDB, Mongoose |
| Cryptography | RSA-PSS, ECDH P-256, HKDF-SHA-256, AES-256-GCM |

## Project Structure

```text
secure-e2ee-messaging-system/
|-- backend/
|   |-- config/          # Database connection
|   |-- controllers/     # Authentication, keys, messages, and files
|   |-- middleware/      # JWT route protection
|   |-- models/          # MongoDB schemas
|   |-- routes/          # REST API routes
|   |-- utils/           # Replay protection and security logging
|   `-- server.js        # Express and Socket.IO server
|-- frontend/
|   |-- public/
|   `-- src/
|       |-- components/  # Application screens
|       |-- context/     # Authentication and theme state
|       |-- services/    # REST and Socket.IO clients
|       `-- utils/       # Cryptography and browser key storage
|-- attack-demos/        # Live MITM and replay test scripts
|-- DATABASE_SCHEMA.md
`-- package.json         # Repository-level development commands
```

## Prerequisites

- Node.js 18 or later
- npm
- MongoDB Community Server or a MongoDB Atlas connection
- A modern browser with Web Crypto API and IndexedDB support

## Environment Variables

Create `backend/.env` from `backend/.env.example`:

```env
PORT=5000
MONGODB_URI=mongodb://localhost:27017/secure-chat
JWT_SECRET=replace_with_a_long_random_secret
JWT_EXPIRE=7d
CLIENT_URL=http://localhost:3000
NODE_ENV=development
```

For a hosted MongoDB database, replace `MONGODB_URI` with the Atlas connection string. Multiple frontend origins can be supplied in `CLIENT_URL` as a comma-separated list.

The frontend defaults to the local backend. For another API host, create `frontend/.env`:

```env
REACT_APP_API_URL=http://localhost:5000/api
REACT_APP_SOCKET_URL=http://localhost:5000
```

## Run Locally

Install all dependencies from the repository root:

```bash
npm run install:all
```

Start MongoDB, then open two terminals.

Terminal 1:

```bash
npm run dev:backend
```

Terminal 2:

```bash
npm run dev:frontend
```

Open `http://localhost:3000`. The API health endpoint is available at `http://localhost:5000/api/health`.

## Using the App

1. Register two accounts in separate browser profiles or browsers.
2. Generate identity keys from each account's dashboard.
3. Add the other user as a contact.
4. Initiate the secure key exchange and accept it from the second account.
5. Send encrypted text messages or files.

Browser storage is profile-specific. Clearing site data removes locally stored identity and session keys, so a new key exchange will be required.

## API Overview

| Area | Base Route | Purpose |
| --- | --- | --- |
| Authentication | `/api/auth` | Register, log in, and verify sessions |
| Identity keys | `/api/keys` | Upload and retrieve public keys |
| Key exchange | `/api/key-exchange` | Initiate, respond to, and finalize exchanges |
| Messages | `/api/messages` | Store and retrieve encrypted messages |
| Files | `/api/files` | Store and retrieve encrypted files |
| Users | `/api/users` | Find users and contacts |

All routes except registration, login, and health checks require a valid bearer token.

## Security Demonstrations

The scripts in `attack-demos/` exercise the running API. Configure their base URL or use the local default, create the required test users, and run:

```bash
npm run demo:mitm --prefix attack-demos
npm run demo:replay --prefix attack-demos
```

These scripts are demonstrations, not a formal security proof or penetration-test suite.

## Verification

Build the frontend:

```bash
npm run build
```

Check the backend entry point:

```bash
npm run check:backend
```

## Security Scope

This project demonstrates application-layer encrypted messaging. Browser compromise, malicious extensions, stolen JWTs, compromised endpoints, metadata analysis, and independent key verification remain outside its protection boundary. For production use, add rate limiting, hardened content security policy, secret rotation, monitored log storage, automated tests, and an independent cryptographic review.
