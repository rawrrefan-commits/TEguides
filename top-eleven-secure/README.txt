TOP ELEVEN SECURE V3 — CLOUDFLARE PAGES + FIRESTORE

PENTING:
- Gunakan paket ini, jangan paket server.js sebelumnya.
- Firestore TIDAK perlu diubah: tetap collection `keys`, document = KEY (contoh `keys/vip67`), field `aktif`, `expired`, dan `deviceId`.
- V3 sengaja MEMATIKAN AUTO-LOGIN. Setiap membuka `/` selalu menampilkan halaman Key agar sistem key mudah dites.

CLOUDFLARE PAGES:
- GitHub repository: PRIVATE.
- Connect repository ke Cloudflare Pages.
- Production branch: main.
- Framework preset: None.
- Build command: kosong.
- Build output directory: .
- Root repository harus langsung berisi `_worker.js`, `_routes.json`, `wrangler.toml`, dan folder `assets/`.

CLOUDFLARE PRODUCTION SECRETS:
- FIREBASE_PROJECT_ID
- FIREBASE_CLIENT_EMAIL
- FIREBASE_PRIVATE_KEY
- SESSION_SECRET (minimal 32 karakter)

JANGAN upload serviceAccountKey.json atau private key ke GitHub.

ALUR:
/ -> halaman key
/api/login -> cek Firestore keys/{KEY}
/app -> hanya bisa jika session valid
/calculator.html -> hanya bisa jika session valid
/api/calculate -> perhitungan server-side
