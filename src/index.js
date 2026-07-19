/********************************************************************************
 * Copyright (C) 2023 CoCreate and Contributors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 ********************************************************************************/

// Commercial Licensing Information:
// For commercial use of this software without the copyleft provisions of the AGPLv3,
// you must obtain a commercial license from CoCreate LLC.
// For details, visit <https://cocreate.app/licenses/> or contact us at sales@cocreate.app.

import crypto from 'node:crypto';
import crud from '@cocreate/crud-server';

// ==========================================
// Module-Level Sandbox State (ESM Singleton Container)
// ==========================================
const tokenExpiration = 60; // Token expiration in minutes
const keyPairs = new Map();  // Active public/private cryptographic key pairs
const sessions = new Map();  // In-memory hot session storage cache

/**
 * Generates a new RSA key pair dynamically and tracks its expiration lifecycle.
 * @returns {Object} Newly created key pair configuration
 */
function createKeyPair() {
    // Generate secure 2048-bit RSA keys natively using Node's built-in Crypto module
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    });

    const created = Date.now();
    const keyPair = {
        _id: crypto.randomUUID(),
        privateKey,
        publicKey,
        created,
        expires: created + tokenExpiration * 60 * 1000,
    };

    keyPairs.set(keyPair._id, keyPair);
    return keyPair;
}


/**
 * Deletes an expired or revoked RSA key pair from local tracking.
 * @param {Object} keyPair - The target key pair to remove
 */
function deleteKeyPair(keyPair) {
    if (keyPair && keyPair._id) {
        keyPairs.delete(keyPair._id);
    }
}

/**
 * Helper to encode JSON payloads safely as Base64URL string representations
 */
function base64urlEncode(obj) {
    return Buffer.from(JSON.stringify(obj)).toString('base64url');
}

/**
 * Helper to decode Base64URL strings safely back to JSON objects
 */
function base64urlDecode(str) {
    try {
        return JSON.parse(Buffer.from(str, 'base64url').toString('utf8'));
    } catch {
        return null;
    }
}


/**
 * Creates and signs a new token utilizing the latest available RSA key pair.
 * Generates a zero-dependency RS256 JWT natively.
 */
function encodeToken(organization_id, user_id, clientId, host) {
    let keyPair = null;
    const currentTime = Date.now();
    
    // Prune expired keypairs and locate/reuse a valid active one
    for (const [key, value] of keyPairs) {
        if (currentTime > value.expires) {
            deleteKeyPair(value);
        } else {
            keyPair = value;
        }
    }

    if (!keyPair) {
        keyPair = createKeyPair();
    }

    const iat = Math.floor(currentTime / 1000);
    const exp = iat + (tokenExpiration * 60);

    // Standard JWT Segments (Header containing Key ID + Alg, and standard Payload)
    const header = {
        alg: 'RS256',
        typ: 'JWT',
        kid: keyPair._id
    };

    const payload = {
        user_id,
        clientId,
        iat,
        exp
    };

    const encodedHeader = base64urlEncode(header);
    const encodedPayload = base64urlEncode(payload);
    const signatureInput = `${encodedHeader}.${encodedPayload}`;

    // Cryptographically sign the envelope natively using SHA-256 and RSA Private Key
    const signer = crypto.createSign('RSA-SHA256');
    signer.update(signatureInput);
    const signature = signer.sign(keyPair.privateKey, 'base64url');

    const token = `${signatureInput}.${signature}`;

    const session = { 
        user_id, 
        clientId, 
        token, 
        expires: currentTime + tokenExpiration * 60 * 1000 
    };
    
    sessions.set(clientId, session);

    if (crud) {
        crud.send({
            method: 'object.update',
            host,
            array: 'clients',
            object: {
                _id: clientId,
                session,
            },
            upsert: true,
            organization_id
        });
    }

    return token;
}


/**
 * Reads, parses, and validates the configuration and active state of client sessions.
 */
async function read(organization_id, clientId, host) {
    if (!crud) return null;

    const client = await crud.send({
        method: 'object.read',
        host,
        array: 'clients',
        object: {
            _id: clientId
        },
        organization_id,
    });

    if (client && client.object && client.object.length) {
        sessions.set(clientId, client.object[0].session);
        return client.object[0].session;
    }
    return null;
}


/**
 * Verifies the integrity of a cryptographic token envelope natively.
 */
function verifySignature(token, publicKey) {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) return false;

        const [header, payload, signature] = parts;
        const verifier = crypto.createVerify('RSA-SHA256');
        verifier.update(`${header}.${payload}`);

        return verifier.verify(publicKey, signature, 'base64url');
    } catch {
        return false;
    }
}

/**
 * Verifies and decodes an incoming session token, resolving the associated user identifier.
 * Incorporates local RSA public-key validation before hitting session layers.
 */
async function decodeToken(token, organization_id, clientId, host) {
    if (!token) return {};
    
    const parts = token.split('.');
    if (parts.length !== 3) return {};

    const [headerB64, payloadB64, signatureB64] = parts;
    const header = base64urlDecode(headerB64);
    const payload = base64urlDecode(payloadB64);

    if (!header || !payload) return {};

    // 1. Core Security Check: Identify active signing keys using Key ID (kid)
    const keyPair = keyPairs.get(header.kid);
    if (keyPair) {
        // Reject forged signatures instantly without proceeding to database/session checks
        const isValid = verifySignature(token, keyPair.publicKey);
        if (!isValid) {
            console.warn(`[SECURITY WARNING] Blocked forged token attempt on clientId: ${clientId}`);
            return {};
        }
    }

    const currentTime = Date.now();
    let session = sessions.get(clientId);

    if (!session || session.token !== token) {
        session = await read(organization_id, clientId, host);
    }

    if (session && currentTime < session.expires && session.token === token) {
        return { user_id: session.user_id, expires: session.expires };
    }

    sessions.delete(clientId);
    
    if (crud) {
        crud.send({
            method: 'object.update',
            host,
            array: 'clients',
            object: {
                _id: clientId,
                session: null
            },
            organization_id,
        });
    }

    return {};
}

// Export the API directly as a flat default object manifest
export default {
    createKeyPair,
    deleteKeyPair,
    encodeToken,
    decodeToken,
    read
};