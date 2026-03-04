# sample-internal-gateway-auth-option1

Sample for the Internal Gateway auth flow: **KrakenD** validates Okta and proxies to **Ops App BE**, which issues a short-lived gateway JWT (with identity→role mapping) and exposes JWKS; **mi6** validates the gateway token and uses `req.user.role` for authZ.

## Flow

```
[Login / token reissue]
FE --(Okta token)--> KrakenD
KrakenD --(validate Okta JWT, propagate claims)--> Ops App BE POST /auth/token
Ops App BE --(map identity→role, issue gateway JWT)--> FE

[API calls]
FE --(Gateway token)--> KrakenD
KrakenD --(validate gateway JWT with Ops App BE JWKS)--> mi6
mi6 --(validate token, use req.user.role)--> allow/deny
```

## Contents

| Path | Description |
|------|-------------|
| **krakend/** | KrakenD config: Okta validator for `/auth/token`, Ops App BE JWKS validator for `/api/*`, propagate_claims. |
| **ops-app-be/** | Ops App BE auth service: Okta validation, identity→role mapping, gateway JWT signing, JWKS. Supports both direct Okta token and KrakenD-propagated headers. |
| **mi6/** | mi6 middleware: validate gateway token via Ops App BE JWKS, set `req.user` (incl. `role`). |

## KrakenD

- **krakend/krakend.json**: Replace `{OKTA_DOMAIN}` with your Okta domain; set `host` for `ops-app-be` and `mi6` to your service URLs. JWKS shared cache 15 min.

## Ops App BE (ops-app-be/)

- `src/auth/okta-validator.ts` — Validate Okta token (introspect); used when not behind KrakenD.
- `src/auth/role-mapper.ts` — Map identity (sub, email) to role (env: `ROLE_MAP_JSON`, `DEFAULT_ROLE`).
- `src/auth/gateway-token.ts` — Sign gateway JWT (RS256) with `role` in payload.
- `src/auth/jwks.ts` — Ops App BE JWKS for KrakenD and mi6.
- `src/auth/middleware.ts` — Login: accept Okta token or KrakenD headers (X-User-Id, X-User-Email, X-User-Name); map identity→role; issue token.
- `src/routes/auth.ts` — `POST /auth/token`, `GET /.well-known/jwks.json`.

**Config (env):** `OKTA_ISSUER`, `OKTA_CLIENT_ID`, `GATEWAY_JWT_PRIVATE_KEY`, `GATEWAY_JWT_KID`, `GATEWAY_JWT_ISSUER`, `GATEWAY_JWT_AUDIENCE`, optional `ROLE_MAP_JSON`, `DEFAULT_ROLE`.

## mi6

- `src/auth/gateway-token-validator.ts` — Fetch Ops App BE JWKS, cache, validate gateway JWT (payload includes `role`).
- `src/auth/middleware.ts` — Require valid token, set `req.user` (sub, email, role, etc.) for authZ.

**Config (env):** `GATEWAY_JWKS_URL` (e.g. `https://ops-app-be/.well-known/jwks.json`), optional `GATEWAY_JWKS_CACHE_TTL_MS`, `GATEWAY_JWT_ISSUER`, `GATEWAY_JWT_AUDIENCE`.

## Using this in a real repo

1. Copy **krakend/krakend.json** and substitute Okta domain and backend hosts.
2. Run the auth logic in **ops-app-be** as your Ops App BE (same process or separate service).
3. In mi6, use `req.user.role` for role-based checks after the gateway-token middleware.
4. Add tests and wire secrets (e.g. Vault) as in the PR.

## References

- PR [#1](https://github.com/smalljimmy/sample-internal-gateway-auth-option1/pull/1): full design (KrakenD + Ops App BE + mi6, role management).
- Okta: token introspection / JWKS. RFC 7517 (JWKS), RFC 7519 (JWT).
