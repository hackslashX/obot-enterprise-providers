# Authentik auth provider

Authentik login for Obot using OIDC authorization code flow with S256 PKCE. This provider uses the same oauth2-proxy fork and session protocol as the other Obot providers. Its manifest requires `OBOT_ENTERPRISE_AUTH_PROVIDERS`, available through free Community registration or an Enterprise license.

## Build and test

From this directory:

```sh
go test -race ./...
go vet ./...
go build -o bin/obot-provider .
```

The repository's build, test, vet, and image-packaging scripts discover the new module automatically. To package it with the other enterprise providers, run `make docker-build` from the repository root. Obot must consume that rebuilt enterprise-providers image to include Authentik in its release image.

For local development, build the binary above and add this repository root to `OBOT_SERVER_PROVIDER_REGISTRIES` when starting Obot. Configure the provider under **Identity & Access > Auth Providers**. Obot supplies the callback URL, cookie secret, and session database settings.

## Authentik configuration

Create a confidential OAuth2/OpenID Connect provider and application. Use the default per-application issuer mode, an asymmetric signing key using RS256, and a strict redirect URI matching the callback URL shown in Obot. Select the `openid`, `email`, `profile`, and `offline_access` scope mappings.

Required provider settings:

| Setting | Value |
| --- | --- |
| `OBOT_AUTHENTIK_AUTH_PROVIDER_ISSUER_URL` | Exact HTTPS issuer, such as `https://auth.example.com/application/o/obot/`, including its trailing slash |
| `OBOT_AUTHENTIK_AUTH_PROVIDER_CLIENT_ID` | Confidential application's client ID |
| `OBOT_AUTHENTIK_AUTH_PROVIDER_CLIENT_SECRET` | Confidential application's client secret |
| `OBOT_AUTH_PROVIDER_EMAIL_DOMAINS` | Comma-separated allowed email domains, or `*` |
| `OBOT_AUTH_PROVIDER_COOKIE_SECRET` | Base64 encoding of 16, 24, or 32 random bytes, supplied by Obot |

`OBOT_SERVER_PUBLIC_URL` or `OBOT_SERVER_URL` supplies Obot's public URL. The manifest lists optional PostgreSQL session, refresh interval, and logging settings. PostgreSQL session tables use the `authentik_` prefix.

### Email verification

Authentik's default email scope mapping returns `email_verified: false`. Login will fail until an email scope mapping reports `true` for verified users. Configure email verification, or obtain verification status from a trusted directory, before changing that mapping. Do not assert verification for arbitrary user-supplied email addresses. Both the ID token and userinfo response need `sub`, `email`, and `email_verified`.

Issuer, signature, nonce, CSRF, and verified-email checks remain enabled. There is no unverified-email bypass setting. The provider discovers the userinfo endpoint rather than constructing it from the issuer path. It rejects HTTP issuers and userinfo endpoints, and does not follow userinfo redirects.

## Supported features

- OIDC login and refresh tokens
- Allowed email domains
- Display name and profile picture from userinfo
- Stable login identity based on the OIDC `sub` claim
- Optional group listing, UUID lookup, and direct/inherited membership synchronization
- Cookie or PostgreSQL session storage

## Optional directory access

Create a dedicated Authentik service account with global `authentik_core.view_user` and `authentik_core.view_group` permissions. Use a read-only role rather than superuser access. In **Tokens and App passwords**, create a token for that account with **API** intent. Configure an expiry and rotate it before expiry.

Set `OBOT_AUTHENTIK_AUTH_PROVIDER_API_TOKEN` to that token in Obot's provider configuration. This is separate from the login application's client secret. No second OAuth application or public/private key pair is needed.

By default, directory requests go to the issuer origin plus `/api/v3`. An optional `OBOT_AUTHENTIK_AUTH_PROVIDER_API_BASE_URL` overrides the Authentik instance URL, without `/api/v3` or the application's issuer path. HTTPS is required; redirects are rejected so they cannot forward the API token to another endpoint.

Directory mode requires `preferred_username` in userinfo to match the actual Authentik username. The provider resolves that username and verified email to the API's numeric user ID and returns it as the profile's `id`. The login session still uses `sub`, which may be an opaque hash rather than a directory ID.

The provider implements Obot's endpoints:

- `/obot-list-auth-groups`, paginated group listing and search
- `/obot-get-auth-groups`, UUID-based lookup of current group names
- `/obot-list-user-auth-groups`, direct memberships plus inherited parent groups

Group IDs use `authentik/<group UUID>`. Membership reads check that the user exists and is active, deduplicate ancestors, stop cycles, and fail rather than return partial results on API errors. Requests use timeouts, response-size limits, and validated IDs. Pagination cursors contain page numbers, never URLs to follow with the service token.

Without an API token, directory endpoints return 404 and OIDC login remains available. The profile omits its directory lookup ID so Obot can resolve it when directory access is enabled later. Raw group-name claims are always discarded. SCIM provisioning is not implemented.

See [Authentik's OIDC documentation](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/) and Obot's authentication-provider setup documentation.
