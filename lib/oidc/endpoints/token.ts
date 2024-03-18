/*!
 * Copyright (c) 2015-present, Okta, Inc. and/or its affiliates. All rights reserved.
 * The Okta software accompanied by this notice is provided pursuant to the Apache License, Version 2.0 (the "License.")
 *
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * 
 * See the License for the specific language governing permissions and limitations under the License.
 */


import { AuthSdkError } from '../../errors';
import { CustomUrls, OAuthParams, OAuthResponse, RefreshToken, TokenParams } from '../types';
import { removeNils, toQueryString } from '../../util';
import { httpRequest, OktaAuthHttpInterface } from '../../http';
import { generateDPoPForTokenRequest, isDPoPNonceError } from '../dpop';

interface TokenRequestParams {
  url: string;
  data: any;
  dpop?: boolean;
  nonce?: string;
}

function validateOptions(options: TokenParams) {
  // Quick validation
  if (!options.clientId) {
    throw new AuthSdkError('A clientId must be specified in the OktaAuth constructor to get a token');
  }

  if (!options.redirectUri) {
    throw new AuthSdkError('The redirectUri passed to /authorize must also be passed to /token');
  }

  if (!options.authorizationCode && !options.interactionCode) {
    throw new AuthSdkError('An authorization code (returned from /authorize) must be passed to /token');
  }

  if (!options.codeVerifier) {
    throw new AuthSdkError('The "codeVerifier" (generated and saved by your app) must be passed to /token');
  }
}

function getPostData(sdk, options: TokenParams): string {
  // Convert Token params to OAuth params, sent to the /token endpoint
  var params: OAuthParams = removeNils({
    'client_id': options.clientId,
    'redirect_uri': options.redirectUri,
    'grant_type': options.interactionCode ? 'interaction_code' : 'authorization_code',
    'code_verifier': options.codeVerifier
  });

  if (options.interactionCode) {
    params['interaction_code'] = options.interactionCode;
  } else if (options.authorizationCode) {
    params.code = options.authorizationCode;
  }

  const { clientSecret } = sdk.options;
  if (clientSecret) {
    params['client_secret'] = clientSecret;
  }

  // Encode as URL string
  return toQueryString(params).slice(1);
}

async function makeTokenRequest (sdk, { url, data, dpop, nonce }: TokenRequestParams): Promise<OAuthResponse> {
  const method = 'POST';
  const headers: any = {
    'Content-Type': 'application/x-www-form-urlencoded',
  };

  if (dpop || sdk.options.dpop) {
    const proof = await generateDPoPForTokenRequest({ url, method, nonce });
    headers.DPoP = proof;
  }

  try {
    const resp = await httpRequest(sdk, {
      url,
      method,
      args: data,
      headers
    });
    return resp;
  }
  catch (err) {
    if (isDPoPNonceError(err) && !nonce) {
      const nonce = err.resp?.headers['dpop-nonce'];
      return makeTokenRequest(sdk, { url, data, dpop, nonce });
    }
    throw err;
  }
}

// exchange authorization code for an access token
export async function postToTokenEndpoint(sdk, options: TokenParams, urls: CustomUrls): Promise<OAuthResponse> {
  validateOptions(options);
  var data = getPostData(sdk, options);

  return makeTokenRequest(sdk, {
    url: urls.tokenUrl!,
    data,
    dpop: options.dpop
  });
}

export async function postRefreshToken(
  sdk: OktaAuthHttpInterface,
  options: TokenParams,
  refreshToken: RefreshToken
): Promise<OAuthResponse> {
  const data = Object.entries({
    client_id: options.clientId, // eslint-disable-line camelcase
    grant_type: 'refresh_token', // eslint-disable-line camelcase
    scope: refreshToken.scopes.join(' '),
    refresh_token: refreshToken.refreshToken, // eslint-disable-line camelcase
  }).map(function ([name, value]) {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return name + '=' + encodeURIComponent(value!);
  }).join('&');

  return makeTokenRequest(sdk, {
    url: refreshToken.tokenUrl,
    data,
    dpop: options.dpop
  });
}
