// References:
// https://www.w3.org/TR/WebCryptoAPI/#concepts-key-storage
// https://datatracker.ietf.org/doc/html/rfc9449

import {
  webcrypto,
  stringToBase64Url,
  stringToBuffer,
  bufferToBase64Url,
  base64ToBase64Url,
} from '../crypto';
import { AuthSdkError, OAuthError, isOAuthError } from '../errors';
import { Tokens, AccessToken } from './types';

export interface DPoPClaims {
  htm: string;
  htu: string;
  iat: number;
  jti: string;
  nonce?: string;
  ath?: string;
}

export interface DPoPProofParams {
  keyPair: CryptoKeyPair;
  url: string;
  method: string;
  nonce?: string;
  accessToken?: AccessToken;
}

export type ResourceDPoPProofParams = Omit<DPoPProofParams, 'keyPair' | 'nonce'>;
type DPoPProofTokenRequestParams = Omit<DPoPProofParams, 'accessToken'>;
// https://developer.mozilla.org/en-US/docs/Web/API/IDBObjectStore#instance_methods
// add additional methods as needed
type StoreMethod = 'get' | 'put' | 'delete' | 'clear';

const INDEXEDDB_NAME = 'OktaAuthJs';

export function isDPoPNonceError(obj: any): obj is OAuthError {
  return (
    isOAuthError(obj) &&
    obj.errorCode === 'use_dpop_nonce' &&
    obj.errorSummary === 'Authorization server requires nonce in DPoP proof.'
  );
}

/////////// crytpo ///////////

export async function writeJwt(header: object, claims: object, signingKey: CryptoKey): Promise<string> {
  const head = stringToBase64Url(JSON.stringify(header));
  const body = stringToBase64Url(JSON.stringify(claims));
  const signature = await webcrypto.subtle.sign(
    { name: signingKey.algorithm.name }, signingKey, stringToBuffer(`${head}.${body}`)
  );
  return `${head}.${body}.${base64ToBase64Url(bufferToBase64Url(signature))}`;
}

export function cryptoRandomValue (byteLen = 32) {
  return [...webcrypto.getRandomValues(new Uint8Array(byteLen))].map(v => v.toString(16)).join('');
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

/////////// indexeddb / keystore ///////////

// convenience abstraction for exposing IDBObjectStore instance
function keyStore (onsuccess: (store: IDBObjectStore) => void,  onerror: (error: Error) => void) {
  const dbKey = 'DPoPKeys';
  const indexedDB = window.indexedDB;
  const req = indexedDB.open(INDEXEDDB_NAME, 1);

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

// convenience abstraction for wrapping IDBObjectStore methods in promises
function invokeStoreMethod (method: StoreMethod, ...args: any[]): Promise<IDBRequest> {
  return new Promise((resolve, reject) => {
    keyStore(function (store) {
      // https://github.com/microsoft/TypeScript/issues/49700
      // https://github.com/microsoft/TypeScript/issues/49802
      // @ts-expect-error ts(2556)
      const req = store[method](...args);
      req.onsuccess = function () {
        resolve(req);
      };
      req.onerror = function () {
        reject(req.error);
      };
    }, reject);
  });
}

async function storeKeyPair (pairId: string, keyPair: CryptoKeyPair) {
  await invokeStoreMethod('put', {id: pairId, keyPair});
  return keyPair;
}

/////////// exported key pair methods ///////////

// attempts to find keyPair stored at given key, otherwise throws
export async function findKeyPair (pairId?: string): Promise<CryptoKeyPair> {
  if (pairId) {
    const req = await invokeStoreMethod('get', pairId);
    if (req.result?.keyPair) {
      return req.result?.keyPair;
    }
  }

  // defaults to throwing unless keyPair is found
  throw new AuthSdkError(`Unable to locate dpop key pair required for refresh (${pairId})`);
}

export async function clearDPoPKeyPair (pairId?: string): Promise<void> {
  if (pairId) {
    await invokeStoreMethod('delete', pairId);
  }
  else {
    await invokeStoreMethod('clear');
  }
}

// will clear PK from storage if certain token conditions are met
export async function clearDPoPKeyPairAfterRevoke (revokedToken: 'access' | 'refresh', tokens: Tokens): Promise<void> {
  let shouldClear = false;

  const { accessToken, refreshToken } = tokens;

  // revoking access token and refresh token doesn't exist
  if (revokedToken === 'access' && accessToken && accessToken.tokenType === 'DPoP' && !refreshToken) {
    shouldClear = true;
  }

  // revoking refresh token and access token doesn't exist
  if (revokedToken === 'refresh' && refreshToken && !accessToken) {
    shouldClear = true;
  }

  const pairId = accessToken?.dpopPairId ?? refreshToken?.dpopPairId;
  if (shouldClear && pairId) {
    await clearDPoPKeyPair(pairId);
  }
}

// generates a crypto (non-extractable) private key pair and writes it to indexeddb, returns key (id)
export async function createDPoPKeyPair (): Promise<{keyPair: CryptoKeyPair, keyPairId: string}> {
  const keyPairId = cryptoRandomValue(4);
  const keyPair = await generateKeyPair();
  await storeKeyPair(keyPairId, keyPair);
  return { keyPair, keyPairId };
}

/////////// exported proof generation methods ///////////

export async function generateDPoPProof ({ keyPair, url, method, nonce, accessToken }: DPoPProofParams): Promise<string> {
  const { kty, crv, e, n, x, y } = await webcrypto.subtle.exportKey('jwk', keyPair.publicKey);
  // TODO: support other alg (listed on well-known)
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
    const ath = await webcrypto.subtle.digest('SHA-256', stringToBuffer(accessToken.accessToken));
    claims.ath = stringToBase64Url(ath);
  }

  return writeJwt(header, claims, keyPair.privateKey);
}

/* eslint max-len: [2, 125] */
export async function generateDPoPForTokenRequest ({ keyPair, url, method, nonce }: DPoPProofTokenRequestParams): Promise<string> {
  const params: DPoPProofParams = { keyPair, url, method };
  if (nonce) {
    params.nonce = nonce;
  }

  return generateDPoPProof(params);
}
