# Pass Offline — Proton Pass (Android + Browser Extension) Offline Build

Fork of Proton Pass sources with these changes:

1. **Offline storage** — items (passwords, passkeys, TOTP) are stored locally; no Proton server storage.
2. **No limits** — plan-based caps on items/passkeys/TOTP removed (unlimited).
3. **Backup export/import** — local JSON backup (Android) and built-in export (extension).
4. **No auto-update** — in-app update checks and update servers fully removed (Android uses the no-op update module).
5. **Google Drive backup** — replaces Proton sync: encrypted (AES-GCM) backups to the user's own Google Drive.

## Layout
- `android/pass/` — Android app source (Proton Pass fork). Debug APK in Releases.
- `extension/` — browser extension source (`pass-extension/` + shared `packages-pass/` store code).

## Build
- Android: `cd android/pass && ./gradlew :app:assemblePlayProdDebug`
- Extension: `pnpm install --frozen-lockfile && pnpm run build:extension` (requires access to pkg.protontech.ch for private packages)
