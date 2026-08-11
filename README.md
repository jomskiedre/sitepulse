# SitePulse Cloud v2 — Google Search Console ready

This version adds a real Google Search Console OAuth flow.

## Deploy
Use Render or another Python host. Render's documented Flask setup uses:
- Build: `pip install -r requirements.txt`
- Start: `gunicorn app:app`

## Required environment variables
- SECRET_KEY
- DATABASE_URL
- GOOGLE_CLIENT_ID
- GOOGLE_CLIENT_SECRET
- GOOGLE_REDIRECT_URI

Optional:
- ADMIN_EMAIL
- ADMIN_PASSWORD

## Google Cloud setup
Create a Google Cloud OAuth 2.0 Web application client. Enable the Search Console API and configure the OAuth consent screen. Add your exact deployed callback URL:

`https://YOUR-DOMAIN/gsc/callback`

Google requires OAuth 2.0 for Search Console private user data.

## User flow
1. User signs up/logs in.
2. Adds a website.
3. Clicks "Connect Search Console".
4. Google consent screen appears.
5. User selects the Search Console property.
6. SitePulse stores the authorized connection.
7. "Sync keywords" pulls the last 28 complete days into the dashboard.

The Search Console API can group search traffic by query, page, country and device and supports date ranges and filters.

## Production security
Before charging customers:
- Encrypt OAuth refresh tokens at rest.
- Add CSRF protection.
- Add rate limiting.
- Add email verification and password reset.
- Add organization/customer roles.
- Add privacy/consent controls and retention settings.
- Use persistent PostgreSQL with automated backups.
- Add a background job for large Search Console syncs.
