# @cocreate/authentication

A high-performance, native RS256 JWT session management and authentication engine. Designed as a zero-dependency ESM singleton cache layer, this engine dynamically provisions 2048-bit RSA keypairs, signs non-opaque session tokens, syncs live connection statuses back to databases via CoCreate CRUD gateways, and runs fast local public-key signature verification to guard distributed nodes against forged requests.

---

## Table of Contents

* [Features](#features)
* [Installation](#installation)
* [Usage](#usage)
* [How it Works](#how-it-works)
* [API Reference](#api-reference)
* [How to Contribute](#how-to-contribute)
* [License](#license)

---

## Features

* **Zero-Dependency Native RS256:** Leverages Node's internal `node:crypto` subsystem to sign and verify JSON Web Tokens (JWT) using asymmetric cryptography without relying on massive external dependencies.
* **Ephemeral Key-Pair Lifecycles:** Automatically provisions 2048-bit RSA key pairs, assigns isolated tracker IDs (`kid`), and handles local cache purging when lifetimes expire.
* **Multi-Layered Hot Cache:** Accelerates performance by keeping active key pairs and client connections within rapid-access memory structures (`Map`), dropping signature evaluation latency to a minimum.
* **CRUD Gateway Synchronization:** Seamlessly broadcasts active user sessions and lifecycle states down to persistent target database collections via internal protocol events (`object.update`).
* **Fast Signature Guard:** Isolates signature validations from state persistence layers, checking incoming signatures against active in-memory keys to drop structural forgery attempts instantly before making database round trips.

---

## Installation

```bash
npm install @cocreate/authentication

```

---

## Usage

### Token Issuance (Session Generation)

Generate a cryptographically signed RS256 token for a successful client connection and synchronize the state into database layers:

```javascript
import auth from '@cocreate/authentication';

const sessionParams = {
  organization_id: "64b9a32e18f21bc56789abcd",
  user_id: "64b9a35f18f21bc5e9812456",
  clientId: "client_ws_90210_alpha",
  host: "app.cocreate.js"
};

// Creates/reuses keys, signs the JWT, and saves the session
const token = auth.encodeToken(
  sessionParams.organization_id,
  sessionParams.user_id,
  sessionParams.clientId,
  sessionParams.host
);

console.log("Generated JWT:", token);

```

### Token Verification & Decoding

Intercept incoming request channels, extract identity records, and catch forged signatures locally:

```javascript
import auth from '@cocreate/authentication';

const inboundToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6...";
const context = {
  organization_id: "64b9a32e18f21bc56789abcd",
  clientId: "client_ws_90210_alpha",
  host: "app.cocreate.js"
};

// Verifies integrity against local keys and falls back to structural DB records if required
const session = await auth.decodeToken(
  inboundToken,
  context.organization_id,
  context.clientId,
  context.host
);

if (!session.user_id) {
  console.log("Authentication Failed: Session missing, expired, or signature forged.");
} else {
  console.log(`Authenticated User: ${session.user_id}, Expires at: ${session.expires}`);
}

```

---

## How it Works

1. **Lifecycle Rotation & Key Selection:** When `encodeToken` runs, the engine checks its active in-memory cache map. It automatically prunes expired keys and searches for a valid, unexpired asymmetric pair. If none are found, it triggers a 2048-bit RSA generation run.
2. **Asymmetric Envelope Signing:** It constructs standard JSON Web Token blocks (Header with `kid` + Payload with `user_id` and timestamps), serializes them into Base64URL string footprints, and signs the unified buffer natively via an asymmetric SHA-256 algorithm.
3. **Persisted State Bridging:** Once the token is assembled, the engine logs the structure into local memory slots and issues asynchronous events (`object.update`) down to central arrays to keep database records aligned with client connection parameters.
4. **Signature Pre-Screening:** During decoding checks (`decodeToken`), the engine parses the incoming header instantly to read the key identification string (`kid`). If that key is cached locally, it executes an direct crypto check (`verifySignature`). Forged payloads are intercepted and dropped right here, skipping down-stream infrastructure operations.
5. **State Invalidation & Synchronization:** If local signatures check out but matching memory records are absent (e.g., when scaled out across distributed processes), it sends query lookups down to persistent storage (`read`). If the token is verified to be expired or invalid, the engine clears all local tracking points and flags the database to nullify the state.

---

## API Reference

### Default Manifest Exports

| Method Selector | Payload Input Structure | Returns | Role |
| --- | --- | --- | --- |
| **`createKeyPair()`** | *None* | `Object` | Generates a new secure 2048-bit RSA key pair object with automatic expiration tracking. |
| **`deleteKeyPair(keyPair)`** | `keyPair: Object` | `Boolean` | Explicitly removes targeted cryptographic configurations from the local tracking cache. |
| **`encodeToken(orgId, userId, clientId, host)`** | `String, String, String, String` | `String` | Generates a zero-dependency RS256 token, assigns local session parameters, and pushes changes to databases. |
| **`decodeToken(token, orgId, clientId, host)`** | `String, String, String, String` | `Object` | Decodes signatures, catches structural forgery attempts instantly, and returns verified identity states. |
| **`read(orgId, clientId, host)`** | `String, String, String` | `Promise<Object|null>` | Reaches out into data backends via internal CRUD pathways to retrieve active persistent session payloads. |

---

## How to Contribute

We encourage contribution to our libraries (you might even score some nifty swag), please see our [CONTRIBUTING.md](https://github.com/CoCreateJS/authentication/blob/master/CONTRIBUTING.md) guide for details. If you encounter any bugs or wish to make feature requests, please submit an issue on our [GitHub Issues](https://github.com/CoCreateJS/authentication/issues) tracker. We want this library to be community-driven, and CoCreate led. We need your help to realize this goal.

For broader system configurations and API guides, please visit our [CoCreate Authentication Documentation](https://cocreatejs.com/docs/authentication).

---

## License

This software is dual-licensed under the GNU Affero General Public License version 3 (AGPLv3) and a commercial license.

* **Open Source Use:** For open-source projects and non-commercial use, this software is available under the AGPLv3. For the full license text, see the LICENSE file.
* **Commercial Use:** For-profit companies and individuals intending to use this software for commercial purposes must obtain a commercial license. The commercial license is available when you sign up for an API key on our website.