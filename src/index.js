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

import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import crud from '@cocreate/crud-server';

// ==========================================
// Module-Level Sandbox State (ESM Singleton Container)
// ==========================================
const tokenExpiration = 60; // Token expiration in minutes
const keyPairs = new Map();
const sessions = new Map();

/**
 * Generates a new RSA key pair dynamically and tracks its expiration lifecycle.
 * @returns {Object} Newly created key pair configuration
 */
function createKeyPair() {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
    });

    const created = new Date(new Date().toISOString()).getTime();
    const keyPair = {
        _id: crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2),
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
 * Creates and signs a new token utilizing the latest available RSA key pair.
 * Saves session markers back to storage and registers client tracking nodes.
 */
function encodeToken(organization_id, user_id, clientId, host) {
    let keyPair = null;
    const currentTime = new Date(new Date().toISOString()).getTime();
    
    for (let [key, value] of keyPairs) {
        if (currentTime > value.expires) {
            deleteKeyPair(value);
        } else {
            keyPair = value;
        }
    }

    if (!keyPair) {
        keyPair = createKeyPair();
    }

    const token = jwt.sign({ user_id, clientId }, keyPair.privateKey, { 
        algorithm: 'RS256', 
        expiresIn: tokenExpiration * 60 
    });

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
 * Verifies and decodes an incoming session token, resolving the associated user identifier.
 */
async function decodeToken(token, organization_id, clientId, host) {
    if (!token) return {};
    
    const currentTime = new Date().getTime();
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