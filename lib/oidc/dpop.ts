// References:
// https://www.w3.org/TR/WebCryptoAPI/#concepts-key-storage

import {
  webcrypto,
  stringToBase64Url,
  stringToBuffer,
  bufferToBase64Url,
  base64ToBase64Url
} from '../crypto';
import { OAuthError, isOAuthError } from '../errors';

export interface DPoPClaims {
  htm: string;
  htu: string;
  iat: number;
  jti: string;
  nonce?: string;
  ath?: string;
}

export interface DPoPProofParams {
  url: string;
  method: string;
  nonce?: string;
  accessToken?: string;
}

type DPoPProofTokenRequestParams = Omit<DPoPProofParams, 'accessToken'>;

export function isDPoPNonceError(obj: any): obj is OAuthError {
  return (
    isOAuthError(obj) &&
    obj.errorCode === 'use_dpop_nonce' &&
    obj.errorSummary === 'Authorization server requires nonce in DPoP proof.'
  );
}

function keyStore (onsuccess: (store: IDBObjectStore) => void,  onerror: (error: Error) => void) {
  const dbKey = 'DPoPKeys';
  // TODO: is this needed?
  // const indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB;
  const indexedDB = window.indexedDB;

  const req = indexedDB.open('OktaAuthJs', 1);

  req.onerror = function () {
    // TODO: throw error
    onerror(req.error!);
  };

  req.onupgradeneeded = function () {
    const db = req.result;
    db.createObjectStore(dbKey, { keyPath: 'id' });
  };

  req.onsuccess = function () {
    const db = req.result;
    const tx = db.transaction(dbKey, 'readwrite');

    tx.onerror = function () {
      // TODO: throw error
      onerror(tx.error!);
    };

    const store = tx.objectStore(dbKey);

    onsuccess(store);

    tx.oncomplete = function () {
      db.close();
    };
  };
}

function loadKeyPair (): Promise<CryptoKeyPair | null> {
  return new Promise((resolve, reject) => {
    keyStore(function (store) {
      const req = store.get(1);
      req.onsuccess = function () {
        resolve(req.result?.keyPair || null);
      };
      req.onerror = function () {
        // TODO: throw error
        reject(req.error);
      };
    }, reject);
  });
}

function storeKeyPair (keyPair: CryptoKeyPair) {
  return new Promise((resolve, reject) => {
    keyStore(function (store) {
      const req = store.put({id: 1, keyPair});
      req.onsuccess = function () {
        resolve(keyPair);
      };
      req.onerror = function () {
        // TODO: throw error
        reject(req.error);
      };
    }, reject);
  });
}

// Exposed as public method, automatically called in tokenManager.remove and .clear
export async function clearDPoPKeyPair (): Promise<void> {
  return new Promise((resolve, reject) => {
    keyStore(function (store) {
      const req = store.clear();
      req.onsuccess = function () {
        resolve();
      };
      req.onerror = function () {
        // TODO: throw error
        reject(req.error);
      };
    }, reject);
  });
}

// load from storage or generate and store keyPair
async function getDPoPKeyPair (): Promise<CryptoKeyPair> {
  let keyPair = await loadKeyPair();
  if (keyPair) {
    return keyPair;
  }
  keyPair = await generateKeyPair();
  await storeKeyPair(keyPair);
  return keyPair;
}

export async function writeJwt(header: object, claims: object, signingKey: CryptoKey): Promise<string> {
  const head = stringToBase64Url(JSON.stringify(header));
  const body = stringToBase64Url(JSON.stringify(claims));
  const signature = await webcrypto.subtle.sign(
    { name: signingKey.algorithm.name }, signingKey, stringToBuffer(`${head}.${body}`)
  );
  return `${head}.${body}.${base64ToBase64Url(bufferToBase64Url(signature))}`;
}

export async function generateKeyPair (): Promise<CryptoKeyPair> {
  const algorithm = {
    name: 'RSASSA-PKCS1-v1_5',
    hash: 'SHA-256',
    modulusLength: 2048,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
  };

  // The "false" here makes it non-exportable
  // https://caniuse.com/mdn-api_subtlecrypto_generatekey
  return webcrypto.subtle.generateKey(algorithm, false, ['sign', 'verify']);
}

export function cryptoRandomValue () {
  return [...webcrypto.getRandomValues(new Uint8Array(32))].map(v => v.toString(16)).join('');
}

export async function generateDPoPProof ({ url, method, nonce, accessToken }: DPoPProofParams): Promise<string> {
  // loadKey
  const key: CryptoKeyPair = await getDPoPKeyPair();

  // public key
  const { kty, crv, e, n, x, y } = await webcrypto.subtle.exportKey('jwk', key.publicKey);
  const header = {
    alg: 'RS256',
    typ: 'dpop+jwt',
    jwk: { kty, crv, e, n, x, y }
  };

  const claims: DPoPClaims = {
    htm: method,
    htu: url,
    iat: Math.floor(Date.now() / 1000),
    jti: cryptoRandomValue(),
  };

  if (nonce) {
    claims.nonce = nonce;
  }

  // encode access token
  if (accessToken) {
    const ath = await webcrypto.subtle.digest('SHA-256', stringToBuffer(accessToken));
    claims.ath = stringToBase64Url(ath);
  }

  return writeJwt(header, claims, key.privateKey);
}

/* eslint max-len: [2, 125] */
export async function generateDPoPForTokenRequest ({ url, method, nonce }: DPoPProofTokenRequestParams): Promise<string> {
  const params: DPoPProofParams = { url, method };
  if (nonce) {
    params.nonce = nonce;
  }

  return generateDPoPProof(params);
}
