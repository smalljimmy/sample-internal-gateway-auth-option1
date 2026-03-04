/**
 * Ops App BE auth middleware:
 * - Login: validate Okta token (or trust propagated claims from KrakenD), map identity→role, issue gateway token.
 * - Optional: validate gateway token on selected routes (same process as mi6).
 */

import type { Request, Response, NextFunction } from 'express';
import { introspectOktaToken } from './okta-validator';
import { issueGatewayToken, verifyGatewayToken } from './gateway-token';
import { mapIdentityToRole } from './role-mapper';
import type { OktaConfig } from './okta-validator';
import type { GatewayTokenConfig } from './gateway-token';

export interface AuthMiddlewareDeps {
  okta: OktaConfig;
  gatewayToken: GatewayTokenConfig;
  gatewayPublicKeyPem: string;
}

/** Headers set by KrakenD when proxying to Ops App BE after Okta validation */
const PROPAGATED_HEADERS = {
  sub: 'x-user-id',
  email: 'x-user-email',
  name: 'x-user-name',
} as const;

/**
 * Extract Bearer token from Authorization header.
 */
function getBearerToken(req: Request): string | null {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return null;
  return auth.slice(7).trim() || null;
}

/**
 * Build identity from KrakenD-propagated headers (when request came via KrakenD).
 * Only trust when all required identity headers are present.
 */
function getIdentityFromPropagatedHeaders(req: Request): { sub: string; email?: string; name?: string } | null {
  const sub = req.headers[PROPAGATED_HEADERS.sub] as string | undefined;
  if (!sub?.trim()) return null;
  return {
    sub: sub.trim(),
    email: (req.headers[PROPAGATED_HEADERS.email] as string | undefined)?.trim(),
    name: (req.headers[PROPAGATED_HEADERS.name] as string | undefined)?.trim(),
  };
}

/**
 * Validate Okta token and issue gateway token. Use in POST /auth/token.
 * Supports two modes:
 * 1) KrakenD: identity comes from propagated claims (X-User-Id, X-User-Email, X-User-Name); skip Okta validation.
 * 2) Direct: body/header contains Okta access token; validate with Okta then issue.
 */
export function createLoginHandler(deps: AuthMiddlewareDeps) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const propagated = getIdentityFromPropagatedHeaders(req);
      let sub: string;
      let email: string | undefined;
      let name: string | undefined;

      if (propagated) {
        sub = propagated.sub;
        email = propagated.email;
        name = propagated.name;
      } else {
        const accessToken =
          (req.body?.accessToken as string) ?? getBearerToken(req);
        if (!accessToken) {
          res.status(400).json({ error: 'missing access token' });
          return;
        }
        const claims = await introspectOktaToken(accessToken, deps.okta);
        if (!claims) {
          res.status(401).json({ error: 'invalid or expired Okta token' });
          return;
        }
        sub = claims.sub;
        email = claims.email;
        name = claims.name;
      }

      const role = await mapIdentityToRole({ sub, email, name });
      const gatewayToken = issueGatewayToken(
        sub,
        { email, name, role },
        deps.gatewayToken
      );

      res.json({ token: gatewayToken, expiresIn: deps.gatewayToken.expiresInSeconds ?? 900, role });
    } catch (err) {
      next(err);
    }
  };
}

/**
 * Middleware: require valid gateway token and set req.user (for Ops App BE–internal routes).
 */
export function createRequireGatewayToken(deps: AuthMiddlewareDeps) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const token = getBearerToken(req);
    if (!token) {
      res.status(401).json({ error: 'missing gateway token' });
      return;
    }
    const payload = verifyGatewayToken(token, deps.gatewayPublicKeyPem);
    if (!payload) {
      res.status(401).json({ error: 'invalid or expired gateway token' });
      return;
    }
    (req as Request & { user: typeof payload }).user = payload;
    next();
  };
}
