# Security Demonstrations

These scripts exercise a running instance of the encrypted messaging API.

## Setup

Install dependencies:

```bash
npm install
```

Start the backend and create the test accounts expected by each script. The default API endpoint is `http://localhost:5000/api`.

To target another server:

```powershell
$env:API_URL="https://example.com/api"
```

## Commands

Run the signed key-exchange demonstration:

```bash
npm run demo:mitm
```

Run the message replay-protection demonstration:

```bash
npm run demo:replay
```

The demonstrations help inspect expected controls and API responses. They are not a formal cryptographic proof, vulnerability assessment, or penetration test.
