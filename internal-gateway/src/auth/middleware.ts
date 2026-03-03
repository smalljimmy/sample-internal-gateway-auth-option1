/**
 * Gateway auth middleware:
 * - Login: validate Okta token, issue gateway token (used in POST /auth/token).
 * - Optional: validate gateway token on selected routes (same process as mi6).
 */

import type { Request, Response, NextFunction } from 'express';
import { introspectOktaToken } from './okta-validator';
import { issueGatewayToken, verifyGatewayToken } from './gateway-token';
import type { OktaConfig } from './okta-validator';
import type { GatewayTokenConfig } from './gateway-token';

export interface AuthMiddlewareDeps {
  okta: OktaConfig;
  gatewayToken: GatewayTokenConfig;
  gatewayPublicKeyPem: string;
}

/**
 * Extract Bearer token from Authorization header.
 */
function getBearerToken(req: Request): string | null {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return null;
  return auth.slice(7).trim() || null;
}

/**
 * Validate Okta token and issue gateway token. Use in POST /auth/token.
 * Expects body: { accessToken: string } (Okta access token).
 */
export function createLoginHandler(deps: AuthMiddlewareDeps) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
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

      const gatewayToken = issueGatewayToken(
        claims.sub,
        { email: claims.email, name: claims.name },
        deps.gatewayToken
      );

      res.json({ token: gatewayToken, expiresIn: deps.gatewayToken.expiresInSeconds ?? 900 });
    } catch (err) {
      next(err);
    }
  };
}

/**
 * Middleware: require valid gateway token and set req.user (for gateway-internal routes).
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
