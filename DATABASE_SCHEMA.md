# Database Schema

MongoDB stores encrypted application data through four Mongoose models.

## User

- Unique username
- bcrypt password hash
- Public identity key in JWK format
- Key algorithm and fingerprint
- Account and last-login timestamps

Private identity keys are stored by the frontend in browser IndexedDB and are not included in this collection.

## KeyExchange

- Initiator and responder references
- Initiator and responder exchange payloads
- Exchange status
- Creation and expiration timestamps

Pending exchanges expire after five minutes through a MongoDB TTL index.

## Message

- Sender and receiver references
- AES-GCM ciphertext and initialization vector
- Message type and optional encrypted-file metadata
- Unique nonce, message sequence, and client timestamp
- Delivery and read status

Conversation, unread-message, nonce, and sequence indexes support retrieval and replay validation.

## File

- Sender and receiver references
- Encrypted file payload and initialization vector
- File name, MIME type, and size metadata
- Creation timestamp

Encrypted file records expire after 30 days through a MongoDB TTL index.
