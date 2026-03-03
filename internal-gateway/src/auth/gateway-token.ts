/**
 * Issues gateway JWTs signed with the gateway's own key (RS256).
 * mi6 will validate these using the gateway's public key from JWKS.
 */

import { createSign, createVerify } from 'crypto';

export interface GatewayTokenConfig {
  privateKeyPem: string;
  keyId: string;
  issuer: string;
  audience: string;
  expiresInSeconds?: number;
}

export interface GatewayTokenPayload {
  sub: string;
  email?: string;
  name?: string;
  iat: number;
  exp: number;
  iss: string;
  aud: string;
}

/**
 * Sign a gateway JWT (RS256) with claims from Okta.
 */
export function issueGatewayToken(
  oktaSub: string,
  options: { email?: string; name?: string },
  config: GatewayTokenConfig
): string {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + (config.expiresInSeconds ?? 900); // default 15 min
  const header = {
    alg: 'RS256',
    typ: 'JWT',
    kid: config.keyId,
  };
  const payload: GatewayTokenPayload = {
    sub: oktaSub,
    email: options.email,
    name: options.name,
    iat: now,
    exp,
    iss: config.issuer,
    aud: config.audience,
  };

  const b64 = (buf: Buffer) => buf.toString('base64url');
  const headerB64 = b64(Buffer.from(JSON.stringify(header)));
  const payloadB64 = b64(Buffer.from(JSON.stringify(payload)));
  const signingInput = `${headerB64}.${payloadB64}`;

  const sign = createSign('RSA-SHA256');
  sign.update(signingInput);
  sign.end();
  const signature = sign.sign(config.privateKeyPem);
  return `${signingInput}.${b64(signature)}`;
}

/**
 * Verify a gateway JWT (e.g. for gateway-internal use). For mi6, use JWKS.
 */
export function verifyGatewayToken(
  token: string,
  publicKeyPem: string
): GatewayTokenPayload | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [headerB64, payloadB64, sigB64] = parts;
  const signingInput = `${headerB64}.${payloadB64}`;
  const signature = Buffer.from(sigB64, 'base64url');

  const verify = createVerify('RSA-SHA256');
  verify.update(signingInput);
  verify.end();
  if (!verify.verify(publicKeyPem, signature)) return null;

  try {
    const payload = JSON.parse(
      Buffer.from(payloadB64, 'base64url').toString('utf8')
    ) as GatewayTokenPayload;
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp < now || payload.iat > now) return null;
    return payload;
  } catch {
    return null;
  }
}
