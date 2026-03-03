/**
 * Validates gateway-issued JWTs using the Internal Gateway's JWKS.
 * Fetches JWKS once (or with TTL cache) and verifies signature + exp.
 */

import { createVerify } from 'crypto';

const DEFAULT_CACHE_TTL_MS = 5 * 60 * 1000; // 5 min

export interface GatewayValidatorConfig {
  jwksUrl: string;
  cacheTtlMs?: number;
  issuer?: string;
  audience?: string;
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

interface CachedJwks {
  keys: Map<string, string>; // kid -> PEM
  fetchedAt: number;
}

/**
 * Fetch JWKS and build kid -> public key PEM map.
 */
async function fetchJwks(jwksUrl: string): Promise<Map<string, string>> {
  const res = await fetch(jwksUrl);
  if (!res.ok) throw new Error(`JWKS fetch failed: ${res.status}`);
  const body = (await res.json()) as { keys?: Array<{ kid?: string; kty: string; n: string; e: string }> };
  const keys = body.keys ?? [];
  const map = new Map<string, string>();
  for (const jwk of keys) {
    if (jwk.kty !== 'RSA' || !jwk.n || !jwk.e || !jwk.kid) continue;
    const pem = jwkToPem(jwk);
    map.set(jwk.kid, pem);
  }
  return map;
}

/**
 * Convert JWK (RSA) to PEM. In production use a library (e.g. "jose" or "jwk-to-pem").
 * This is a minimal placeholder for the sample; replace with import from "jose" etc.
 */
function jwkToPem(jwk: { n: string; e: string }): string {
  // Example: with "jose": const key = await jose.importJWK(jwk); return (await jose.exportSPKI(key)) as string;
  const n = Buffer.from(jwk.n, 'base64url');
  const e = Buffer.from(jwk.e, 'base64url');
  const len = 2 + n.length + 2 + e.length;
  const buf = Buffer.alloc(4 + len);
  let o = 0;
  buf[o++] = 0x30; buf[o++] = 0x82; buf[o++] = (len + 2) >> 8; buf[o++] = (len + 2) & 0xff;
  buf[o++] = 0x02; buf[o++] = 0x82; buf[o++] = n.length >> 8; buf[o++] = n.length & 0xff;
  n.copy(buf, o); o += n.length;
  buf[o++] = 0x02; buf[o++] = 0x03; e.copy(buf, o);
  const b64 = buf.toString('base64');
  return ['-----BEGIN PUBLIC KEY-----', ...(b64.match(/.{1,64}/g) ?? []), '-----END PUBLIC KEY-----'].join('\n');
}

/**
 * Validator that caches JWKS and validates gateway tokens.
 */
export function createGatewayTokenValidator(config: GatewayValidatorConfig) {
  let cache: CachedJwks | null = null;
  const ttl = config.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;

  async function getKeys(): Promise<Map<string, string>> {
    const now = Date.now();
    if (cache && now - cache.fetchedAt < ttl) return cache.keys;
    const keys = await fetchJwks(config.jwksUrl);
    cache = { keys, fetchedAt: now };
    return keys;
  }

  async function validate(token: string): Promise<GatewayTokenPayload | null> {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    let header: { kid?: string; alg?: string };
    try {
      header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    } catch {
      return null;
    }
    const kid = header.kid;
    if (!kid) return null;
    const keys = await getKeys();
    const publicKeyPem = keys.get(kid);
    if (!publicKeyPem) return null;

    const signingInput = `${parts[0]}.${parts[1]}`;
    const signature = Buffer.from(parts[2], 'base64url');
    const verify = createVerify('RSA-SHA256');
    verify.update(signingInput);
    verify.end();
    if (!verify.verify(publicKeyPem, signature)) return null;

    let payload: GatewayTokenPayload;
    try {
      payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) as GatewayTokenPayload;
    } catch {
      return null;
    }
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp < now || payload.iat > now) return null;
    if (config.issuer != null && payload.iss !== config.issuer) return null;
    if (config.audience != null && payload.aud !== config.audience) return null;
    return payload;
  }

  return { validate, getKeys };
}
