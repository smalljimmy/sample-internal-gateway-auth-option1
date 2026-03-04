# KrakenD config (Internal Gateway)

Replace placeholders before use:

- `{OKTA_DOMAIN}` — Your Okta domain (e.g. `dev-12345.okta.com`). Use in `jwk_url` and `issuer` for the `/auth/token` endpoint.
- `ops-app-be:3000` / `mi6:4000` — Set to your Ops App BE and mi6 backend URLs (host/port or full URL).

Run: `krakend run -c krakend.json` (or use KrakenD FC for env-based config).
