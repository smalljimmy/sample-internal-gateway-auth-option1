/**
 * Auth routes: exchange Okta token (or KrakenD-propagated identity) for gateway token, serve JWKS.
 * When behind KrakenD, POST /auth/token receives X-User-Id, X-User-Email, X-User-Name from gateway.
 */

import { Router } from 'express';
import { createLoginHandler } from '../auth/middleware';
import { buildJwks } from '../auth/jwks';
import type { AuthMiddlewareDeps } from '../auth/middleware';

export function createAuthRouter(deps: AuthMiddlewareDeps, jwksConfig: { privateKeyPem: string; keyId: string }) {
  const router = Router();

  router.post('/auth/token', createLoginHandler(deps));

  router.get('/.well-known/jwks.json', (_req, res) => {
    res.set('Cache-Control', 'public, max-age=300');
    res.json(buildJwks(jwksConfig));
  });

  return router;
}
