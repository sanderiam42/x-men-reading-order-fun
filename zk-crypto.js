// zk-crypto.js - Zero-knowledge encryption utilities for state sync
// Implements HKDF, AES-GCM encryption, and HMAC-SHA256 for secure state storage

/**
 * Base64url encode a Uint8Array
 */
function base64urlEncode(bytes) {
  const base64 = btoa(String.fromCharCode(...bytes));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Base64url decode to Uint8Array
 */
function base64urlDecode(str) {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}

/**
 * Concatenate multiple Uint8Arrays
 */
function concatUint8Arrays(...arrays) {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * HKDF key derivation using SubtleCrypto
 */
async function HKDF(passphrase, info, lengthBytes, saltB64u) {
  const enc = new TextEncoder();
  const salt = base64urlDecode(saltB64u);
  
  // Import the passphrase as a raw key
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  
  // Derive key using PBKDF2
  const derivedKey = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256"
    },
    keyMaterial,
    { name: "HKDF", hash: "SHA-256" },
    false,
    ["deriveBits"]
  );
  
  // Derive the final bits
  const infoBytes = enc.encode(info);
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt,
      info: infoBytes
    },
    derivedKey,
    lengthBytes * 8
  );
  
  return new Uint8Array(derivedBits);
}

/**
 * Derive a stable ID from passphrase
 */
export async function deriveId(passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const saltB64u = base64urlEncode(salt);
  const idBytes = await HKDF(passphrase, "id", 16, saltB64u);
  return base64urlEncode(idBytes);
}

/**
 * Encrypt a JSON object with AES-GCM and HMAC
 */
export async function encryptJson(obj, passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const saltB64u = base64urlEncode(salt);
  
  // Derive encryption and MAC keys
  const encKey = await HKDF(passphrase, "enc", 32, saltB64u);
  const macKey = await HKDF(passphrase, "mac", 32, saltB64u);
  
  // Import keys for crypto operations
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    encKey,
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  );
  
  const hmacKey = await crypto.subtle.importKey(
    "raw",
    macKey,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  
  // Encrypt the JSON
  const plaintext = new TextEncoder().encode(JSON.stringify(obj));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    cryptoKey,
    plaintext
  );
  const ct = new Uint8Array(ciphertext);
  
  // Compute HMAC over salt || iv || ciphertext
  const macData = concatUint8Arrays(salt, iv, ct);
  const mac = await crypto.subtle.sign("HMAC", hmacKey, macData);
  const macBytes = new Uint8Array(mac);
  
  return {
    v: 1,
    ts: Date.now(),
    salt: saltB64u,
    iv: base64urlEncode(iv),
    ct: base64urlEncode(ct),
    mac: base64urlEncode(macBytes)
  };
}

/**
 * Verify HMAC and decrypt JSON object
 */
export async function verifyAndDecrypt(payload, passphrase) {
  try {
    // Validate payload structure
    if (!payload || typeof payload !== 'object' || 
        payload.v !== 1 || 
        typeof payload.salt !== 'string' ||
        typeof payload.iv !== 'string' ||
        typeof payload.ct !== 'string' ||
        typeof payload.mac !== 'string' ||
        typeof payload.ts !== 'number') {
      throw new Error('Invalid payload structure');
    }
    
    const salt = base64urlDecode(payload.salt);
    const iv = base64urlDecode(payload.iv);
    const ct = base64urlDecode(payload.ct);
    const mac = base64urlDecode(payload.mac);
    const saltB64u = payload.salt;
    
    // Derive keys
    const encKey = await HKDF(passphrase, "enc", 32, saltB64u);
    const macKey = await HKDF(passphrase, "mac", 32, saltB64u);
    
    // Import keys
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      encKey,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );
    
    const hmacKey = await crypto.subtle.importKey(
      "raw",
      macKey,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );
    
    // Verify HMAC
    const macData = concatUint8Arrays(salt, iv, ct);
    const macValid = await crypto.subtle.verify(
      "HMAC",
      hmacKey,
      mac,
      macData
    );
    
    if (!macValid) {
      throw new Error('HMAC verification failed');
    }
    
    // Decrypt
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      cryptoKey,
      ct
    );
    
    const jsonStr = new TextDecoder().decode(plaintext);
    return JSON.parse(jsonStr);
    
  } catch (error) {
    console.error('Decryption failed:', error);
    throw new Error('Decryption failed: ' + error.message);
  }
}

