// Client-side authentication service for unified server-first auth
// Handles PBKDF2 key derivation and AES-GCM unwrapping for WebCrypto interoperability

const textEncoder = new TextEncoder();

// Convert base64 string to ArrayBuffer for WebCrypto
function base64ToArrayBuffer(base64) {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

// Convert ArrayBuffer to base64 string
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Derive wrap key from password using PBKDF2
 * @param {string} password - User password
 * @param {string} saltB64 - Base64 encoded salt
 * @param {number} iterations - KDF iterations
 * @returns {Promise<CryptoKey>} Derived wrap key for unwrapping DEK
 */
export async function deriveWrapKey(password, saltB64, iterations) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  
  const salt = base64ToArrayBuffer(saltB64);
  
  return await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
}

/**
 * Unwrap DEK using AES-GCM
 * For WebCrypto interoperability, we concatenate ciphertext + auth tag before decryption
 * This matches the server's Node.js crypto format where tag is separate
 * @param {Object} wrapped - Object with iv, ct, tag (all base64)
 * @param {CryptoKey} wrapKey - Key to unwrap with
 * @returns {Promise<ArrayBuffer>} Raw DEK (32 bytes)
 */
export async function unwrapDEK(wrapped, wrapKey) {
  const iv = base64ToArrayBuffer(wrapped.iv);
  const ct = base64ToArrayBuffer(wrapped.ct);
  const tag = base64ToArrayBuffer(wrapped.tag);
  
  // WebCrypto expects ciphertext + tag concatenated for AES-GCM
  const ctWithTag = new Uint8Array(ct.byteLength + tag.byteLength);
  ctWithTag.set(new Uint8Array(ct));
  ctWithTag.set(new Uint8Array(tag), ct.byteLength);
  
  return await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    wrapKey,
    ctWithTag
  );
}

/**
 * Import raw DEK bytes as AES-GCM key for file encryption
 * @param {ArrayBuffer} raw32 - 32-byte raw key material
 * @returns {Promise<CryptoKey>} Import DEK as AES-GCM key
 */
export async function importDEK(raw32) {
  return await crypto.subtle.importKey(
    'raw',
    raw32,
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Decrypt wrapped DEK using password
 * @param {Object} params - { password, wrapped, kdfSalt, kdfIterations }
 * @returns {Promise<CryptoKey>} Imported DEK ready for file encryption/decryption
 */
export async function decryptWrappedDEK({ password, wrapped, kdfSalt, kdfIterations }) {
  const wrapKey = await deriveWrapKey(password, kdfSalt, kdfIterations);
  const rawDEK = await unwrapDEK(wrapped, wrapKey);
  return await importDEK(rawDEK);
}

// LocalStorage keys for auth metadata
const AUTH_META_KEY = 'sv_auth_meta';

/**
 * Load authentication metadata from localStorage
 * @returns {Object|null} Auth metadata or null if not found
 */
export function loadAuthMeta() {
  try {
    const raw = localStorage.getItem(AUTH_META_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

/**
 * Store authentication metadata to localStorage
 * @param {Object} meta - { email, kdfSalt, kdfIterations, wrappedDEK_pw }
 */
export function storeAuthMeta(meta) {
  localStorage.setItem(AUTH_META_KEY, JSON.stringify(meta));
}

/**
 * Clear authentication metadata from localStorage
 */
export function clearAuthMeta() {
  localStorage.removeItem(AUTH_META_KEY);
}