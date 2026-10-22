/** Sign-in endpoints shield watches by default, with the body field that names the account. */
export const SIGN_IN_PATHS: Record<string, string> = {
  "/sign-in/email": "email",
  "/sign-in/username": "username",
  "/sign-in/phone-number": "phoneNumber",
  "/sign-in/identifier": "identifier",
  "/sign-in/email-otp": "email",
};

/**
 * Error codes that mean "wrong secret". Only these count as failures: a 403 for
 * an unverified email, for example, comes after a correct password.
 */
export const FAILURE_CODES = new Set([
  "INVALID_EMAIL_OR_PASSWORD",
  "INVALID_USERNAME_OR_PASSWORD",
  "INVALID_PHONE_NUMBER_OR_PASSWORD",
  "INVALID_OTP",
  "OTP_EXPIRED",
  "TOO_MANY_ATTEMPTS",
]);

/** Longest identifier hashed; longer input is cut so a huge body can't cost an expensive hash. */
const MAX_LENGTH = 320;

/**
 * Folds the forms Better Auth would treat as one account into one key: Unicode
 * compatibility forms, case, surrounding whitespace and, for phone numbers, the
 * usual separators. Merging slightly more than Better Auth does only means two
 * near-identical identifiers share a counter; merging less would let an
 * attacker reset the counter by changing case.
 */
export function normalizeIdentifier(field: string, value: unknown): string | null {
  if (typeof value !== "string") return null;
  let id = value.slice(0, MAX_LENGTH).normalize("NFKC").trim().toLowerCase();
  if (field === "phoneNumber") id = id.replace(/[\s().-]/g, "");
  return id || null;
}

const encoder = new TextEncoder();
const keys = new Map<string, Promise<CryptoKey>>();

/**
 * HMAC-SHA-256 of the identifier, keyed with the auth secret. Counters and the
 * event log store only this, never the email or username itself.
 */
export async function hashIdentifier(secret: string, identifier: string): Promise<string> {
  let key = keys.get(secret);
  if (!key) {
    key = crypto.subtle.importKey("raw", encoder.encode(`better-auth-shield:${secret}`), { name: "HMAC", hash: "SHA-256" }, false, [
      "sign",
    ]);
    keys.set(secret, key);
  }
  const mac = await crypto.subtle.sign("HMAC", await key, encoder.encode(identifier));
  return Array.from(new Uint8Array(mac), (b) => b.toString(16).padStart(2, "0")).join("");
}
