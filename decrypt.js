const $ = s => document.querySelector(s);
const b64ToU8 = b64 => Uint8Array.from(atob(b64), c => c.charCodeAt(0));

// Notification system for cloud sync status
function showNotification(message, type = 'info') {
  const status = $("#status");
  if (status) {
    status.textContent = message;
    status.className = `status ${type}`;
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
      if (status.textContent === message) {
        status.textContent = '';
        status.className = 'status';
      }
    }, 5000);
  }
}

async function deriveKey(passphrase, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 210000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
}

async function decryptBlob(blob, passphrase) {
  const salt = b64ToU8(blob.salt);
  const iv   = b64ToU8(blob.iv);
  const tag  = b64ToU8(blob.tag);
  const ct   = b64ToU8(blob.ciphertext);
  const key  = await deriveKey(passphrase, salt);

  // Append the tag to ciphertext for SubtleCrypto
  const ctPlusTag = new Uint8Array(ct.length + tag.length);
  ctPlusTag.set(ct, 0);
  ctPlusTag.set(tag, ct.length);

  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv, tagLength: 128 },
    key,
    ctPlusTag
  );
  return new TextDecoder().decode(pt);
}

async function unlock(passphrase) {
  try {
    console.log("Starting unlock process...");
    
    // Optional: read manifest for future versions/multiple files
    console.log("Fetching manifest...");
    const manifest = await (await fetch("./manifest.json", { cache: "no-store" })).json();
    console.log("Manifest loaded:", manifest);

    // 1) Decrypt data first, then expose as global EXTRACTED_PAYLOAD
    console.log("Fetching data.enc.json...");
    const dataEnc = await (await fetch("./data.enc.json", { cache: "no-store" })).json();
    console.log("Data encrypted blob loaded");
    
    console.log("Decrypting data...");
    const dataJson = await decryptBlob(dataEnc, passphrase);
    console.log("Data decrypted, length:", dataJson.length);
    
    try {
      // Find the last } and extract only the JSON part
      const lastBrace = dataJson.lastIndexOf('}');
      if (lastBrace === -1) {
        throw new Error("No closing brace found in decrypted data");
      }
      const jsonPart = dataJson.substring(0, lastBrace + 1);
      console.log("JSON part length:", jsonPart.length);
      window.EXTRACTED_PAYLOAD = JSON.parse(jsonPart);
      console.log("Data parsed successfully, keys:", Object.keys(window.EXTRACTED_PAYLOAD));
    } catch (e) {
      console.error("JSON parsing failed:", e);
      throw new Error("Decrypted data is not valid JSON: " + e.message);
    }

    // 2) Decrypt HTML
    console.log("Fetching html.enc...");
    const htmlEnc = await (await fetch("./html.enc", { cache: "no-store" })).json();
    console.log("HTML encrypted blob loaded");
    
    console.log("Decrypting HTML...");
    const html = await decryptBlob(htmlEnc, passphrase);
    console.log("HTML decrypted, length:", html.length);

    // 3) Mount: the HTML should not redeclare EXTRACTED_PAYLOAD;
    //    it may reference the placeholder <!-- PAYLOAD_WILL_BE_INJECTED_BY_BOOTSTRAP -->
    //    which we need to replace with the actual payload:
    console.log("Processing HTML...");
    const app = $("#app");
    
    // Store passphrase temporarily in sessionStorage for cloud sync
    // This is more secure than global scope but still not ideal
    sessionStorage.setItem('zk_passphrase_temp', passphrase);
    
    // Clean up passphrase on page unload for security
    window.addEventListener('beforeunload', () => {
      sessionStorage.removeItem('zk_passphrase_temp');
    });
    
    // Replace the placeholder with the actual payload
    const processedHtml = html.replace(
      /const EXTRACTED_PAYLOAD = \{\s*<!-- PAYLOAD_WILL_BE_INJECTED_BY_BOOTSTRAP -->/,
      `const EXTRACTED_PAYLOAD = ${JSON.stringify(window.EXTRACTED_PAYLOAD)};`
    );
    console.log("HTML processed, injecting into DOM...");
    app.innerHTML = processedHtml;
    app.hidden = false;
    
    // Execute the JavaScript in the injected HTML
    console.log("Executing JavaScript in injected HTML...");
    const scripts = app.querySelectorAll('script');
    scripts.forEach(script => {
      const newScript = document.createElement('script');
      newScript.textContent = script.textContent;
      document.head.appendChild(newScript);
    });
    
    // Hide the unlock form after successful decryption
    const unlockForm = document.querySelector('#unlock-form');
    const unlockHeading = document.querySelector('h1');
    const hint = document.querySelector('.hint');
    if (unlockForm) unlockForm.style.display = 'none';
    if (unlockHeading) unlockHeading.style.display = 'none';
    if (hint) hint.style.display = 'none';
    
    // Load cloud state if available
    if (window.ZK_LOAD_STATE) {
      try {
        console.log("Loading cloud state...");
        const { state, error } = await window.ZK_LOAD_STATE(passphrase);
        
        if (state) {
          console.log("Cloud state loaded successfully");
          // Apply cloud state to localStorage if it's newer
          const localState = JSON.parse(localStorage.getItem(`readingState:${window.EXTRACTED_PAYLOAD?.listId || 'locg-unknown'}:v1`) || '{}');
          const cloudTimestamp = state._cloudTimestamp || 0;
          const localTimestamp = localState._lastModified || 0;
          
          if (cloudTimestamp > localTimestamp) {
            console.log("Cloud state is newer, applying to localStorage");
            localStorage.setItem(`readingState:${window.EXTRACTED_PAYLOAD?.listId || 'locg-unknown'}:v1`, JSON.stringify(state));
            // Trigger a page reload to apply the new state
            window.location.reload();
            return;
          }
        } else if (error === "network") {
          console.warn("Cloud sync unavailable; continuing with local data");
          showNotification("Cloud sync unavailable; continuing with local data.", "warning");
        } else if (error === "integrity") {
          console.warn("Cloud version corrupted; using local data");
          showNotification("Cloud version corrupted; using local data.", "warning");
        }
      } catch (error) {
        console.error("Failed to load cloud state:", error);
        showNotification("Failed to load cloud state; using local data.", "error");
      }
    }
    
    console.log("Unlock process completed successfully!");
  } catch (error) {
    console.error("Unlock process failed:", error);
    throw error;
  }
}

$("#unlock-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const passphrase = ($("#passphrase").value || "").trim();
  const status = $("#status");
  status.textContent = "Decrypting…";
  try {
    await unlock(passphrase);
    status.textContent = "";
    sessionStorage.setItem("zk_pass_session", "1"); // in-memory per tab
  } catch (err) {
    console.error(err);
    status.textContent = "Decryption failed. Check your passphrase.";
  }
});
