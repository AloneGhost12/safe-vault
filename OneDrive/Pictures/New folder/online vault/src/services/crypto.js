// Basic client-side crypto helpers using Web Crypto API
// NOTE: This is for demo/local use only; production apps need hardened key management and auditing.

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

const PBKDF2_ITERATIONS = 310000; // Modern browsers can handle this; adjust for performance.

function bufToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function base64ToBuf(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer;
}

export async function createMasterPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const saltB64 = bufToBase64(salt);
  const hash = await hashPassword(password, salt);
  localStorage.setItem('sv_salt', saltB64);
  localStorage.setItem('sv_hash', hash);
  return deriveContentKey(password, salt);
}

export async function unlockWithPassword(password) {
  const saltB64 = localStorage.getItem('sv_salt');
  const storedHash = localStorage.getItem('sv_hash');
  if (!saltB64 || !storedHash) throw new Error('No master password set.');
  const salt = new Uint8Array(base64ToBuf(saltB64));
  const hash = await hashPassword(password, salt);
  if (hash !== storedHash) throw new Error('Incorrect password');
  return deriveContentKey(password, salt);
}

async function hashPassword(password, salt) {
  const data = new Uint8Array([...salt, ...textEncoder.encode(password)]);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return bufToBase64(digest);
}

async function deriveContentKey(password, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  const key = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
  return key;
}

export async function encryptArrayBuffer(key, arrayBuffer) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    arrayBuffer
  );
  return {
    iv: bufToBase64(iv),
    data: bufToBase64(cipher)
  };
}

export async function decryptToArrayBuffer(key, ivB64, dataB64) {
  const iv = new Uint8Array(base64ToBuf(ivB64));
  const data = base64ToBuf(dataB64);
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    data
  );
  return plain;
}

export function hasMasterPassword() {
  return !!(localStorage.getItem('sv_salt') && localStorage.getItem('sv_hash'));
}
