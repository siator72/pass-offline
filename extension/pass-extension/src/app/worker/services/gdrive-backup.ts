/**
 * Google Drive backup service (offline build).
 *
 * Replaces Proton server sync: the user brings their own Google Drive via
 * OAuth (PKCE). Backups are encrypted client-side before upload so the
 * Drive provider never sees plaintext secrets.
 *
 * Required OAuth client setup: the user must register their own OAuth
 * client (Chrome extension / web app type) and set:
 *   PASS_GDRIVE_CLIENT_ID
 *   PASS_GDRIVE_REDIRECT_URI (extension identity redirect URL)
 */

export const GDRIVE_CLIENT_ID = 'PASS_GDRIVE_CLIENT_ID'; // replace at build time
const GDRIVE_SCOPES = ['https://www.googleapis.com/auth/drive.file'];
const BACKUP_MIME = 'application/octet-stream';
const BACKUP_FOLDER_NAME = 'PassOfflineBackup';

export type DriveBackupMeta = {
    name: string;
    fileId: string;
    modifiedTime: string;
    size: string;
};

const base64url = (bytes: Uint8Array): string => {
    let str = '';
    for (const b of bytes) str += String.fromCharCode(b);
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

const fromBase64url = (s: string): Uint8Array => {
    const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};

export const deriveBackupKey = async (passphrase: string): Promise<CryptoKey> =>
    crypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);

export const encryptBackup = async (data: string, passphrase: string): Promise<Uint8Array> => {
    const key = await deriveBackupKey(passphrase);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const aesKey = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: 310_000, hash: 'SHA-256' },
        key,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
    );
    const ciphertext = new Uint8Array(
        await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(data))
    );
    const out = new Uint8Array(salt.length + iv.length + ciphertext.length);
    out.set(salt, 0);
    out.set(iv, salt.length);
    out.set(ciphertext, salt.length + iv.length);
    return out;
};

export const decryptBackup = async (blob: Uint8Array, passphrase: string): Promise<string> => {
    const salt = blob.slice(0, 16);
    const iv = blob.slice(16, 28);
    const ciphertext = blob.slice(28);
    const key = await deriveBackupKey(passphrase);
    const aesKey = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: 310_000, hash: 'SHA-256' },
        key,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
    );
    return new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ciphertext));
};

/* ---------------- OAuth (PKCE) ---------------- */

export const gdriveAuth = async (): Promise<string> => {
    const redirectUri = browser.identity.getRedirectURL();
    const state = base64url(crypto.getRandomValues(new Uint8Array(16)));
    const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
    const challenge = base64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))));

    const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    url.searchParams.set('client_id', GDRIVE_CLIENT_ID);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('scope', GDRIVE_SCOPES.join(' '));
    url.searchParams.set('access_type', 'offline');
    url.searchParams.set('prompt', 'consent');
    url.searchParams.set('code_challenge', challenge);
    url.searchParams.set('code_challenge_method', 'S256');
    url.searchParams.set('state', state);

    const redirect = await browser.identity.launchWebAuthFlow({ url: url.href, interactive: true });
    const redirectUrl = new URL(redirect);
    if (redirectUrl.searchParams.get('state') !== state) throw new Error('OAuth state mismatch');
    const code = redirectUrl.searchParams.get('code');
    if (!code) throw new Error('OAuth code missing');

    const res = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            client_id: GDRIVE_CLIENT_ID,
            code,
            code_verifier: verifier,
            grant_type: 'authorization_code',
            redirect_uri: redirectUri,
        }),
    });
    const tokens = (await res.json()) as { access_token: string };
    if (!tokens.access_token) throw new Error('Token exchange failed');
    await browser.storage.local.set({ gdriveAccessToken: tokens.access_token });
    return tokens.access_token;
};

export const gdriveToken = async (): Promise<string> => {
    const { gdriveAccessToken } = await browser.storage.local.get('gdriveAccessToken');
    if (!gdriveAccessToken) return gdriveAuth();
    const res = await fetch('https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=' + gdriveAccessToken);
    if (res.ok) return gdriveAccessToken as string;
    return gdriveAuth();
};

/* ---------------- Drive API ---------------- */

const findBackupFolder = async (token: string): Promise<string | null> => {
    const q = encodeURIComponent(`name='${BACKUP_FOLDER_NAME}' and mimeType='application/vnd.google-apps.folder' and trashed=false`);
    const res = await fetch(`https://www.googleapis.com/drive/v3/files?q=${q}&fields=files(id)`, {
        headers: { Authorization: `Bearer ${token}` },
    });
    const json = (await res.json()) as { files: { id: string }[] };
    return json.files?.[0]?.id ?? null;
};

const ensureBackupFolder = async (token: string): Promise<string> => {
    const existing = await findBackupFolder(token);
    if (existing) return existing;
    const res = await fetch('https://www.googleapis.com/drive/v3/files', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: BACKUP_FOLDER_NAME, mimeType: 'application/vnd.google-apps.folder' }),
    });
    const json = (await res.json()) as { id: string };
    return json.id;
};

export const gdriveUploadBackup = async (
    payload: string,
    passphrase: string,
    onProgress?: (pct: number) => void
): Promise<DriveBackupMeta> => {
    const token = await gdriveToken();
    onProgress?.(5);
    const encrypted = await encryptBackup(payload, passphrase);
    onProgress?.(35);
    const folderId = await ensureBackupFolder(token);
    const name = `pass-backup-${new Date().toISOString().replace(/[:.]/g, '-')}.bin`;

    const metadata = { name, parents: [folderId], mimeType: BACKUP_MIME };
    const form = new FormData();
    form.append('metadata', new Blob([JSON.stringify(metadata)], { type: 'application/json' }));
    form.append('file', new Blob([encrypted as BlobPart], { type: BACKUP_MIME }));

    const res = await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
        body: form,
    });
    const json = (await res.json()) as { id: string; name: string; mimeType: string };
    if (!json.id) throw new Error('Drive upload failed');
    onProgress?.(100);
    return { name: json.name, fileId: json.id, modifiedTime: json.name, size: String(encrypted.length) };
};

export const gdriveListBackups = async (): Promise<DriveBackupMeta[]> => {
    const token = await gdriveToken();
    const folderId = await findBackupFolder(token);
    if (!folderId) return [];
    const q = encodeURIComponent(`'${folderId}' in parents and trashed=false`);
    const res = await fetch(
        `https://www.googleapis.com/drive/v3/files?q=${q}&orderBy=modifiedTime desc&fields=files(id,name,modifiedTime,size)`,
        { headers: { Authorization: `Bearer ${token}` } }
    );
    const json = (await res.json()) as { files: DriveBackupMeta[] };
    return json.files ?? [];
};

export const gdriveDownloadBackup = async (fileId: string, passphrase: string): Promise<string> => {
    const token = await gdriveToken();
    const res = await fetch(`https://www.googleapis.com/drive/v3/files/${fileId}?alt=media`, {
        headers: { Authorization: `Bearer ${token}` },
    });
    const buf = new Uint8Array(await res.arrayBuffer());
    onDecryptProgress();
    return decryptBackup(buf, passphrase);
};

const onDecryptProgress = () => {};
