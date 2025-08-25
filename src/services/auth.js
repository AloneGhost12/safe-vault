// Server-first authentication helpers for WebCrypto interoperability
// Handles key derivation, DEK unwrapping, and auth metadata persistence

const textEncoder = new TextEncoder();

// Storage keys for auth metadata
const AUTH_META_KEY = 'sv_auth_meta';

// Derive AES-GCM wrap key from password using PBKDF2-SHA256
// Compatible with server-side crypto.pbkdf2Sync
export async function deriveWrapKey(password, saltB64, iterations) {
  const salt = base64ToBuffer(saltB64);
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  const wrapKey = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
  return wrapKey;
}

// Unwrap DEK using WebCrypto AES-GCM
// Server wraps as {iv, ct, tag} - we need to combine ct+tag for WebCrypto decrypt
export async function unwrapDEK(wrapped, wrapKey) {
  const iv = base64ToBuffer(wrapped.iv);
  const ct = base64ToBuffer(wrapped.ct);
  const tag = base64ToBuffer(wrapped.tag);
  
  // WebCrypto expects ciphertext with auth tag appended
  // Server stores them separately, so we combine ct + tag
  const combined = new Uint8Array(ct.byteLength + tag.byteLength);
  combined.set(new Uint8Array(ct), 0);
  combined.set(new Uint8Array(tag), ct.byteLength);
  
  try {
    const dekBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      wrapKey,
      combined
    );
    return new Uint8Array(dekBuffer);
  } catch (e) {
    throw new Error('Failed to unwrap DEK - invalid password or corrupted data');
  }
}

// Import raw 32-byte DEK as AES-GCM CryptoKey for content encryption
export async function importDEK(raw32) {
  return await crypto.subtle.importKey(
    'raw',
    raw32,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// Convenience function: decrypt wrapped DEK and import as CryptoKey
export async function decryptWrappedDEK(password, authMeta) {
  const wrapKey = await deriveWrapKey(password, authMeta.kdfSalt, authMeta.kdfIterations);
  const dekRaw = await unwrapDEK(authMeta.wrappedDEK_pw, wrapKey);
  return await importDEK(dekRaw);
}

// Load persisted auth metadata from localStorage
// Returns null if no metadata exists
export function loadAuthMeta() {
  try {
    const stored = localStorage.getItem(AUTH_META_KEY);
    return stored ? JSON.parse(stored) : null;
  } catch {
    return null;
  }
}

// Store auth metadata in localStorage
// Only stores wrapped/public data - no plaintext passwords or keys
export function storeAuthMeta(meta) {
  try {
    const toStore = {
      email: meta.email,
      kdfSalt: meta.kdfSalt,
      kdfIterations: meta.kdfIterations,
      wrappedDEK_pw: meta.wrappedDEK_pw
    };
    localStorage.setItem(AUTH_META_KEY, JSON.stringify(toStore));
  } catch (e) {
    console.error('Failed to store auth metadata:', e);
  }
}

// Clear auth metadata from localStorage
export function clearAuthMeta() {
  try {
    localStorage.removeItem(AUTH_META_KEY);
  } catch (e) {
    console.error('Failed to clear auth metadata:', e);
  }
}

// Helper: convert base64 to ArrayBuffer
function base64ToBuffer(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer;
}

// Check if user has stored auth metadata (indicates previous registration/login)
export function hasAuthMeta() {
  return !!loadAuthMeta();
}