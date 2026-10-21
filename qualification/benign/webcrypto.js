const data = new TextEncoder().encode(input);
const hash = await window.crypto.subtle.digest("SHA-256", data);
