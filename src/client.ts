import type { BetterAuthClientPlugin } from "better-auth/client";
import type { shield } from "./index.js";
import { ERROR_CODES } from "./error-codes.js";

export { ERROR_CODES } from "./error-codes.js";
export type { ShieldErrorCode } from "./error-codes.js";

/** Client side of better-auth-shield: typed error codes (`ACCOUNT_LOCKED`). */
export const shieldClient = () =>
  ({
    id: "shield",
    $InferServerPlugin: {} as ReturnType<typeof shield>,
    $ERROR_CODES: ERROR_CODES,
  }) satisfies BetterAuthClientPlugin;
