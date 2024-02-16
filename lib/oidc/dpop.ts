
// References:
// https://www.w3.org/TR/WebCryptoAPI/#concepts-key-storage

import { writeJwt, generateKeyPair, exportPublicKey, encodeAccessToken } from '../crypto/dpopUtils';
import { genRandomString } from '../util';
import { AuthSdkError } from '../errors';

export interface DPoPClaims {
  htm: string;
  htu: string;
  iat: number;
  jti: string;
  nonce?: string;
  ath?: string;
};

export interface DPoPProofParams {
  url: string;
  method: string;
  nonce?: string;
  accessToken?: string;
}

type DPoPProofTokenRequestParams = Omit<DPoPProofParams, 'accessToken'>;

function keyStore (onsuccess: (store: IDBObjectStore) => void,  onerror: (error: Error) => void) {
  const dbKey = 'DPoPKeys';
  // TODO: is this needed?
  // const indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB;
  const indexedDB = window.indexedDB;

  const req = indexedDB.open('OktaAuthJs', 1);

  req.onerror = function () {
    // TODO: throw error
    onerror(req.error!);
  }

  req.onupgradeneeded = function () {
    const db = req.result;
    const store = db.createObjectStore(dbKey, { keyPath: 'id' });
  }

  req.onsuccess = function () {
    const db = req.result;
    const tx = db.transaction(dbKey, 'readwrite');

    tx.onerror = function () {
      // TODO: throw error
      onerror(tx.error!);
    }

    const store = tx.objectStore(dbKey);

    onsuccess(store);

    tx.oncomplete = function () {
      db.close();
    }
  }
}

function loadKeyPair (): Promise<CryptoKeyPair | null> {
  return new Promise((resolve, reject) => {
    keyStore(function (store) {
      const req = store.get(1);
      req.onsuccess = function () {
        resolve(req.result?.keyPair || null);
      }
      req.onerror = function () {
        // TODO: throw error
        reject(req.error);
      }
    }, reject);
  });
}

function storeKeyPair (keyPair: CryptoKeyPair) {
  return new Promise((resolve, reject) => {
    keyStore(function (store) {
      const req = store.put({id: 1, keyPair});
      req.onsuccess = function () {
        resolve(keyPair);
      }
      req.onerror = function () {
        // TODO: throw error
        reject(req.error);
      }
    }, reject);
  });
}

// TODO: when/where to invalid key pair?
export async function clearDPoPKeyPair (): Promise<void> {
  return new Promise((resolve, reject) => {
    keyStore(function (store) {
      const req = store.clear();
      req.onsuccess = function () {
        resolve();
      }
      req.onerror = function () {
        // TODO: throw error
        reject(req.error);
      }
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

// TODO: param type
async function generateDPoPProof ({ url, method, nonce, accessToken }: DPoPProofParams) {
  // loadKey
  const key: CryptoKeyPair = await getDPoPKeyPair();

  const header = {
    alg: 'RS256',
    typ: 'dpop+jwt',
    jwk: await exportPublicKey(key.publicKey)
  };

  const claims: DPoPClaims = {
    htm: method,
    htu: url,
    iat: Math.floor(Date.now() / 1000),
    jti: genRandomString(48),
  };

  if (nonce) {
    claims.nonce = nonce;
  }

  if (accessToken) {
    claims.ath = await encodeAccessToken(accessToken);
  }

  return writeJwt(header, claims, key.privateKey);
}

export async function generateDPoPForTokenRequest ({ url, method, nonce }: DPoPProofTokenRequestParams) {
  const params: DPoPProofParams = { url, method };
  if (nonce) {
    params.nonce = nonce;
  }

  return generateDPoPProof(params);
}

export async function generateDPoPForResourceRequest (sdk, { url, method, nonce, accessToken }: DPoPProofParams) {
  const params: DPoPProofParams = { url, method };
  if (nonce) {
    params.nonce = nonce;
  }

  if (!accessToken) {
    const { accessToken } = sdk.tokenManager.getTokensSync();
    params.accessToken = accessToken.accessToken;
    if (!accessToken) {
      throw new AuthSdkError('AccessToken is required to generate a DPoP Proof');
    }
  }

  return generateDPoPProof(params);
}

