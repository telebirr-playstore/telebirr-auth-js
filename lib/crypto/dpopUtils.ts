import { webcrypto } from './webcrypto';
import { stringToBase64Url, stringToBuffer } from './base64';

export async function writeJwt(header: object, claims: object, signingKey: CryptoKey): Promise<string> {
  const head = stringToBase64Url(JSON.stringify(header));
  const body = stringToBase64Url(JSON.stringify(claims));
  const signature = await webcrypto.subtle.sign(
    { name: signingKey.algorithm.name }, signingKey, stringToBuffer(`${head}.${body}`)
  );
  return `${head}.${body}.${signature}`;
};

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

export async function exportPublicKey(publicKey: CryptoKey) {
  const { kty, crv, e, n, x, y } = await webcrypto.subtle.exportKey('jwk', publicKey);
  return { kty, crv, e, n, x, y };
}

export async function encodeAccessToken (accessToken: string) {
  const ath = await webcrypto.subtle.digest('SHA-256', stringToBuffer(accessToken));
  return stringToBase64Url(ath);
}
