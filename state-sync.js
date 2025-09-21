// state-sync.js - Firebase-backed state synchronization with debouncing
import { deriveId, encryptJson, verifyAndDecrypt } from './zk-crypto.js';

// Debounce configuration
let debounceMs = 500;
const debounceTimers = new Map(); // keyed by derived ID

/**
 * Set the cloud save debounce delay
 */
export function setCloudSaveDebounce(ms) {
  debounceMs = ms;
}

/**
 * Get App Check token, return null on failure
 */
async function getAppCheckToken() {
  try {
    if (typeof firebase === 'undefined' || !firebase.appCheck) {
      return null;
    }
    const token = await firebase.appCheck().getToken(true);
    return token?.token || null;
  } catch (error) {
    // Log once per session to avoid spam
    if (!window._appCheckErrorLogged) {
      console.error('App Check token failed:', error);
      window._appCheckErrorLogged = true;
    }
    return null;
  }
}

/**
 * Internal save function that performs immediate PUTs
 */
async function saveStateInternal(passphrase, stateObj) {
  const id = await deriveId(passphrase);
  const encrypted = await encryptJson(stateObj, passphrase);
  const token = await getAppCheckToken();
  
  const headers = {
    'Content-Type': 'application/json'
  };
  
  if (token) {
    headers['X-Firebase-AppCheck'] = token;
  }
  
  const baseUrl = window.FB_FUNCTION_BASE;
  const ts = encrypted.ts;
  
  // PUT to store the version
  const versionResponse = await fetch(`${baseUrl}/${id}/v1/${ts}`, {
    method: 'PUT',
    headers,
    body: JSON.stringify(encrypted)
  });
  
  if (!versionResponse.ok) {
    throw new Error(`Failed to save version: ${versionResponse.status} ${versionResponse.statusText}`);
  }
  
  // PUT to update the latest pointer
  const latestResponse = await fetch(`${baseUrl}/${id}/v1/latest`, {
    method: 'PUT',
    headers,
    body: JSON.stringify({ ts })
  });
  
  if (!latestResponse.ok) {
    throw new Error(`Failed to update latest pointer: ${latestResponse.status} ${latestResponse.statusText}`);
  }
}

/**
 * Debounced save function
 */
export async function saveState(passphrase, stateObj) {
  const id = await deriveId(passphrase);
  
  // Clear existing timer for this ID
  if (debounceTimers.has(id)) {
    clearTimeout(debounceTimers.get(id));
  }
  
  // Set new timer
  const timer = setTimeout(async () => {
    try {
      await saveStateInternal(passphrase, stateObj);
      debounceTimers.delete(id);
    } catch (error) {
      console.error('Cloud save failed:', error);
      debounceTimers.delete(id);
      throw error;
    }
  }, debounceMs);
  
  debounceTimers.set(id, timer);
}

/**
 * Load state from cloud with structured error handling
 */
export async function loadState(passphrase) {
  try {
    const id = await deriveId(passphrase);
    const token = await getAppCheckToken();
    
    const headers = {};
    if (token) {
      headers['X-Firebase-AppCheck'] = token;
    }
    
    const baseUrl = window.FB_FUNCTION_BASE;
    
    // Try to get the latest pointer first
    let latestTs = null;
    try {
      const latestResponse = await fetch(`${baseUrl}/${id}/v1/latest`, { headers });
      
      if (latestResponse.ok) {
        const latestData = await latestResponse.json();
        if (latestData && typeof latestData.ts === 'number') {
          latestTs = latestData.ts;
        }
      } else if (latestResponse.status !== 404) {
        // 404 is expected for new users, other errors are network issues
        throw new Error(`Latest pointer fetch failed: ${latestResponse.status}`);
      }
    } catch (error) {
      console.error('Failed to fetch latest pointer:', error);
      return { state: null, error: "network" };
    }
    
    // If we have a latest pointer, try to load that version
    if (latestTs !== null) {
      try {
        const versionResponse = await fetch(`${baseUrl}/${id}/v1/${latestTs}`, { headers });
        
        if (versionResponse.ok) {
          const versionData = await versionResponse.json();
          const decrypted = await verifyAndDecrypt(versionData, passphrase);
          return { state: decrypted, error: null };
        } else if (versionResponse.status === 404) {
          // Latest pointer exists but version is missing, fall through to list fallback
        } else {
          throw new Error(`Version fetch failed: ${versionResponse.status}`);
        }
      } catch (error) {
        if (error.message.includes('Decryption failed') || error.message.includes('HMAC verification failed')) {
          console.error('Latest version decryption failed:', error);
          // Fall through to list fallback
        } else {
          console.error('Failed to fetch latest version:', error);
          return { state: null, error: "network" };
        }
      }
    }
    
    // Fallback: get list of versions and try to decrypt them
    try {
      const listResponse = await fetch(`${baseUrl}/${id}/v1?limit=20`, { headers });
      
      if (!listResponse.ok) {
        throw new Error(`List fetch failed: ${listResponse.status}`);
      }
      
      const versions = await listResponse.json();
      
      if (!Array.isArray(versions) || versions.length === 0) {
        return { state: null, error: null }; // No state exists yet
      }
      
      // Try versions in reverse chronological order (newest first)
      const sortedVersions = versions
        .filter(v => v && typeof v.ts === 'number')
        .sort((a, b) => b.ts - a.ts);
      
      for (const version of sortedVersions) {
        try {
          const versionResponse = await fetch(`${baseUrl}/${id}/v1/${version.ts}`, { headers });
          
          if (versionResponse.ok) {
            const versionData = await versionResponse.json();
            const decrypted = await verifyAndDecrypt(versionData, passphrase);
            return { state: decrypted, error: null };
          }
        } catch (error) {
          if (error.message.includes('Decryption failed') || error.message.includes('HMAC verification failed')) {
            console.error(`Version ${version.ts} decryption failed:`, error);
            continue; // Try next version
          } else {
            console.error(`Failed to fetch version ${version.ts}:`, error);
            return { state: null, error: "network" };
          }
        }
      }
      
      // All versions failed decryption
      return { state: null, error: "integrity" };
      
    } catch (error) {
      console.error('List fallback failed:', error);
      return { state: null, error: "network" };
    }
    
  } catch (error) {
    console.error('Unexpected error in loadState:', error);
    return { state: null, error: "network" };
  }
}

