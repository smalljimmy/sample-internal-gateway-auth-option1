# Add auth layer to Internal Gateway + mi6 gateway-token validation (Option 1)

## Summary

Implements Option 1 from the Okta SSO / Internal Gateway / mi6 auth design: the Internal Gateway gains an auth layer that validates Okta tokens and issues its own signed JWT (gateway token). The gateway exposes a JWKS endpoint so mi6 can validate gateway tokens without calling the gateway on every request.

## Problem

- Internal Gateway currently has **no auth layer**, so the originally proposed flow (FE → Okta token → Gateway validates → Gateway issues token → FE uses gateway token for mi6) could not work.
- mi6 was expected to validate the gateway token but had no way to do so (no gateway-issued JWT, no public key).

## Solution

1. **Internal Gateway**
   - Validate incoming Okta access tokens (introspect or verify JWT with Okta JWKS).
   - Issue a short-lived **gateway JWT** (signed with gateway’s own key pair).
   - Expose **JWKS** at e.g. `GET /.well-known/jwks.json` so mi6 can fetch the public key.
   - New auth middleware: `validateOktaAndIssueGatewayToken` (login/token endpoint) and optional middleware to validate gateway tokens for gateway-internal use.

2. **mi6**
   - New middleware: validate `Authorization: Bearer <gateway-token>` using the gateway’s public key (fetch once from gateway JWKS, cache).
   - Reject requests with missing/invalid/expired gateway token; attach decoded claims (e.g. `sub`, `email`) for role checks.

## Flow (after change)

```
[Login]
FE --(Okta token)--> Internal Gateway
Internal Gateway --(validate with Okta)--> Okta
Internal Gateway --(issue signed JWT)--> FE

[API calls to mi6]
FE --(Gateway token only)--> mi6
mi6 --(validate with gateway JWKS, cached)--> allow/deny
```

## Changes in this PR

### Internal Gateway

| Path | Description |
|------|-------------|
| `src/auth/okta-validator.ts` | Validates Okta access token (introspect or Okta JWKS). |
| `src/auth/gateway-token.ts` | Signs gateway JWT (RS256), configurable issuer/audience/expiry. |
| `src/auth/jwks.ts` | Serves gateway public key(s) at `/.well-known/jwks.json`. |
| `src/auth/middleware.ts` | Middleware: login flow (validate Okta → issue gateway token) and optional gateway-token validation. |
| `src/routes/auth.ts` | `POST /auth/token` (exchange Okta token for gateway token), `GET /.well-known/jwks.json`. |

### mi6

| Path | Description |
|------|-------------|
| `src/auth/gateway-token-validator.ts` | Fetches gateway JWKS, caches, validates gateway JWT. |
| `src/auth/middleware.ts` | Middleware: require valid gateway token, set `req.user` for role middleware. |

### Config / env

- **Gateway:** `OKTA_ISSUER`, `OKTA_CLIENT_ID`, `GATEWAY_JWT_PRIVATE_KEY` (PEM), `GATEWAY_JWT_KID`, optional `GATEWAY_JWKS_PATH`.
- **mi6:** `GATEWAY_JWKS_URL` (e.g. `https://internal-gateway/.well-known/jwks.json`), optional cache TTL.

## Testing

- **Gateway:** Unit tests for Okta validation, JWT signing, JWKS shape. Integration: `POST /auth/token` with valid/invalid Okta token, then `GET /.well-known/jwks.json`.
- **mi6:** Unit tests for validator (valid token, expired, wrong key). Integration: call mi6 with valid gateway token and with missing/invalid token.

## Security / ops

- Gateway private key in secret store (e.g. Vault); only public key in JWKS.
- Gateway token expiry kept short (e.g. 15–60 min); FE can refresh via same Okta token.
- mi6 caches JWKS with TTL to avoid over-calling gateway; cache invalidation on 4xx from JWKS URL if desired.

## Follow-ups

- [ ] Role-management middleware in mi6 using `req.user` (email/identity from gateway JWT).
- [ ] Metrics/logging for token validation failures and JWKS cache hits/misses.
- [ ] Documentation for FE: obtain gateway token from `POST /auth/token`, use in `Authorization` for mi6.

## References

- Design thread: Internal Gateway + Okta + mi6 auth (Option 1).
- Okta: token introspection / JWKS for access token validation.
- RFC 7517 (JWKS), RFC 7519 (JWT).
