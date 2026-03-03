/**
 * Build and serve JWKS (JSON Web Key Set) for the gateway's public key.
 * mi6 fetches this to validate gateway-issued JWTs.
 */

import { createPublicKey } from 'crypto';

export interface JwksConfig {
  privateKeyPem: string;
  keyId: string;
  alg?: string;
}

/**
 * JWKS document (RFC 7517). Single key for simplicity.
 */
export function buildJwks(config: JwksConfig): { keys: object[] } {
  const publicKey = createPublicKey(config.privateKeyPem);
  const jwk = publicKey.export({ format: 'jwk' }) as {
    n: string;
    e: string;
    kty: string;
    alg?: string;
    kid?: string;
  };
  return {
    keys: [
      {
        ...jwk,
        alg: config.alg ?? 'RS256',
        kid: config.keyId,
        use: 'sig',
      },
    ],
  };
}
