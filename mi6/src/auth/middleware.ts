/**
 * mi6 auth middleware: require valid gateway token and set req.user (incl. role) for authZ.
 * Token is issued by Ops App BE; payload includes role from identity→role mapping.
 */

import type { Request, Response, NextFunction } from 'express';
import { createGatewayTokenValidator, type GatewayTokenPayload } from './gateway-token-validator';
import type { GatewayValidatorConfig } from './gateway-token-validator';

declare global {
  namespace Express {
    interface Request {
      user?: GatewayTokenPayload;
    }
  }
}

function getBearerToken(req: Request): string | null {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return null;
  return auth.slice(7).trim() || null;
}

/**
 * Middleware factory: require valid gateway JWT; set req.user from payload (sub, email, role, etc.).
 */
export function createRequireGatewayTokenMiddleware(config: GatewayValidatorConfig) {
  const validator = createGatewayTokenValidator(config);

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const token = getBearerToken(req);
    if (!token) {
      res.status(401).json({ error: 'missing gateway token' });
      return;
    }
    try {
      const payload = await validator.validate(token);
      if (!payload) {
        res.status(401).json({ error: 'invalid or expired gateway token' });
        return;
      }
      req.user = payload;
      next();
    } catch (err) {
      next(err);
    }
  };
}
