/**
 * Validates Okta access tokens (introspect or verify JWT with Okta JWKS).
 * Used by the gateway before issuing its own JWT.
 */

const OKTA_INTROSPECT_PATH = '/oauth2/v1/introspect';

export interface OktaConfig {
  issuer: string;
  clientId: string;
  clientSecret?: string;
}

export interface OktaClaims {
  sub: string;
  email?: string;
  name?: string;
  exp: number;
  iat?: number;
}

/**
 * Introspect Okta access token. Use when token is opaque.
 * Requires client_secret for confidential clients.
 */
export async function introspectOktaToken(
  accessToken: string,
  config: OktaConfig
): Promise<OktaClaims | null> {
  const url = `${config.issuer}${OKTA_INTROSPECT_PATH}`;
  const body = new URLSearchParams({
    token: accessToken,
    token_type_hint: 'access_token',
  });
  const auth =
    config.clientSecret != null
      ? Buffer.from(`${config.clientId}:${config.clientSecret}`).toString('base64')
      : undefined;

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      ...(auth && { Authorization: `Basic ${auth}` }),
    },
    body: body.toString(),
  });

  if (!res.ok) return null;
  const data = (await res.json()) as { active?: boolean; sub?: string; email?: string; name?: string; exp?: number; iat?: number };
  if (!data.active) return null;

  return {
    sub: data.sub ?? '',
    email: data.email,
    name: data.name,
    exp: data.exp ?? 0,
    iat: data.iat,
  };
}
