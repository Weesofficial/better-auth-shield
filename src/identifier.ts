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

/** Endpoints that email or text a code or link, mapped to the body field naming the recipient. */
export const SEND_PATHS: Record<string, string> = {
  "/email-otp/send-verification-otp": "email",
  "/email-otp/request-password-reset": "email",
  "/forget-password/email-otp": "email",
  "/phone-number/send-otp": "phoneNumber",
  "/phone-number/request-password-reset": "phoneNumber",
  "/request-password-reset": "email",
  "/send-verification-email": "email",
  "/sign-in/magic-link": "email",
};

/**
 * Second-factor endpoints of the `twoFactor` plugin and the codes of a wrong
 * code. Better Auth locks the account itself after repeated failures
 * (`accountLockout`, on by default); shield only records them. Refusals
 * (`ACCOUNT_TEMPORARILY_LOCKED`, `TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE`) are not
 * recorded, so hammering a locked account can't flood the event table.
 */
export const TWO_FACTOR_PATHS = new Set(["/two-factor/verify-totp", "/two-factor/verify-otp", "/two-factor/verify-backup-code"]);
export const TWO_FACTOR_FAILURE_CODES = new Set(["INVALID_CODE", "INVALID_BACKUP_CODE", "OTP_HAS_EXPIRED"]);

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
