# sample-internal-gateway-auth-option1

Sample PR: Option 1 — Auth layer in Internal Gateway (Okta + JWT + JWKS) and mi6 gateway-token validation.

This folder contains a **sample PR** for the Option 1 auth flow (Internal Gateway validates Okta and issues its own JWT; mi6 validates that JWT via the gateway's JWKS).

## Contents

| Path | Description |
|------|-------------|
| **PULL_REQUEST.md** | PR description: summary, problem, solution, file list, testing, follow-ups. |
| **internal-gateway/** | Sample Internal Gateway auth: Okta validation, gateway JWT signing, JWKS endpoint. |
| **mi6/** | Sample mi6 middleware: validate gateway token using gateway JWKS (with cache). |

## Internal Gateway (sample)

- `src/auth/okta-validator.ts` — Validate Okta token (introspect).
- `src/auth/gateway-token.ts` — Sign gateway JWT (RS256), verify with PEM.
- `src/auth/jwks.ts` — Build JWKS from gateway key.
- `src/auth/middleware.ts` — Login handler (Okta → gateway token), optional gateway-token check.
- `src/routes/auth.ts` — `POST /auth/token`, `GET /.well-known/jwks.json`.

**Config (env):** `OKTA_ISSUER`, `OKTA_CLIENT_ID`, `OKTA_CLIENT_SECRET`, `GATEWAY_JWT_PRIVATE_KEY` (PEM), `GATEWAY_JWT_KID`, `GATEWAY_JWT_ISSUER`, `GATEWAY_JWT_AUDIENCE`.

## mi6 (sample)

- `src/auth/gateway-token-validator.ts` — Fetch gateway JWKS, cache, validate gateway JWT.
- `src/auth/middleware.ts` — `createRequireGatewayTokenMiddleware`: require valid token, set `req.user`.

**Config (env):** `GATEWAY_JWKS_URL`, optional `GATEWAY_JWKS_CACHE_TTL_MS`, `GATEWAY_JWT_ISSUER`, `GATEWAY_JWT_AUDIENCE`.

## Using this as a real PR

1. Copy **PULL_REQUEST.md** into your repo as the PR description (e.g. in the GitHub PR body).
2. Adapt the file paths to your Internal Gateway and mi6 repos (or monorepo).
3. Replace sample code with your stack (e.g. use `jose` or `jsonwebtoken` + `jwks-rsa` for JWT/JWKS; keep the same flow).
4. Add tests and wire env/secrets as in the PR "Testing" and "Config" sections.

## Flow (reminder)

```
Login:  FE → (Okta token) → Gateway → validate with Okta → issue gateway JWT → FE
APIs:   FE → (gateway token) → mi6 → validate with gateway JWKS (cached) → allow/deny
```
