/**
 * Plain data, shared by the server plugin and the client so neither pulls the
 * other's dependencies in.
 */
export const ERROR_CODES = {
  ACCOUNT_LOCKED: {
    code: "ACCOUNT_LOCKED",
    message: "Too many failed attempts. Try again later.",
  },
  SEND_LIMITED: {
    code: "SEND_LIMITED",
    message: "Too many codes or links requested. Try again later.",
  },
} as const;

export type ShieldErrorCode = keyof typeof ERROR_CODES;
