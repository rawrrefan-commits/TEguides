TOP ELEVEN SECURE V4 - CLOUDFLARE PAGES FUNCTIONS

Repository structure:
  functions/_middleware.js
  assets/index.html
  assets/calculator.html
  _routes.json
  wrangler.toml

Cloudflare Pages Git settings:
  Production branch: main
  Build command: empty
  Build output directory: assets

IMPORTANT:
- Do NOT upload Firebase serviceAccountKey.json to GitHub.
- Keep these Cloudflare Production Secrets:
  FIREBASE_PROJECT_ID
  FIREBASE_CLIENT_EMAIL
  FIREBASE_PRIVATE_KEY
  SESSION_SECRET

Firestore structure remains:
  keys/{KEY}
  fields: aktif, expired, deviceId

Open the site through HTTPS, not file://.
The root / is the public key login page. /app and calculator.html require a valid session.
