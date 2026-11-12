const INVITATION_PATTERN = /^([a-f0-9]{48}):([A-Za-z0-9_-]{43})$/;

export function parseInvitation(value) {
  const match = INVITATION_PATTERN.exec(String(value || "").trim());
  if (!match) {
    throw new Error("Invitation format is invalid. Paste the complete private invitation.");
  }

  const encodedKey = match[2];
  const normalized = encodedKey.replace(/-/g, "+").replace(/_/g, "/") + "=";
  let decoded;
  try {
    decoded = atob(normalized);
  } catch {
    throw new Error("Invitation key is invalid.");
  }
  if (decoded.length !== 32) {
    throw new Error("Invitation key is invalid.");
  }

  return { code: match[1], key: encodedKey };
}

export function createInvitation(code, bytes) {
  if (!/^[a-f0-9]{48}$/.test(String(code || "")) ||
      !(bytes instanceof Uint8Array) || bytes.length !== 32) {
    throw new Error("Could not create a valid private invitation.");
  }
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  const key = btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  const invitation = code + ":" + key;
  parseInvitation(invitation);
  return invitation;
}
