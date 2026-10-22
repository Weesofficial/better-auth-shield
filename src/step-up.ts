import type { AuthContext, BetterAuthPlugin, Session } from "better-auth";
import { APIError, createAuthEndpoint, createAuthMiddleware, getSessionFromCtx, sessionMiddleware } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import { z } from "zod";
import type { CounterStore, LockRule } from "./counter.js";
import { ERROR_CODES } from "./error-codes.js";
import { TWO_FACTOR_FAILURE_CODES } from "./identifier.js";
import { checkCount, type Emit } from "./password.js";

export const STEP_UP_FIELD = "stepUpAt";

/** Better Auth endpoints that need a recent step-up unless `stepUp.paths` says otherwise. */
export const STEP_UP_PATHS = [
  "/change-email",
  "/email-otp/request-email-change",
  "/email-otp/change-email",
  "/delete-user",
  "/link-social",
  "/unlink-account",
  "/passkey/generate-register-options",
  "/passkey/verify-registration",
  "/two-factor/disable",
  "/two-factor/generate-backup-codes",
  // Approving a device hands it a new session, which would count as a fresh sign-in.
  "/device/approve",
  "/admin/impersonate-user",
  "/admin/set-role",
  // Can set the role and email too.
  "/admin/update-user",
  "/admin/create-user",
  "/admin/set-user-password",
  "/admin/remove-user",
  "/api-key/create",
];

export interface StepUpOptions {
  /** Seconds a step-up (or a new sign-in) counts as recent. Defaults to 300. */
  maxAge?: number;
  /** Endpoints that need a recent step-up. Replaces `STEP_UP_PATHS`; spread it to extend. */
  paths?: string[];
}

/** Second-factor checks on a signed-in session, and the method each one is. */
const VERIFY_PATHS: Record<string, string> = {
  "/two-factor/verify-totp": "totp",
  "/two-factor/verify-otp": "otp",
  "/two-factor/verify-backup-code": "backup_code",
};

/** Other signed-in endpoints that check the password; their wrong guesses count toward the same lock. */
const PASSWORD_CHECK_PATHS = new Set(["/change-password", "/two-factor/enable", "/two-factor/get-totp-uri", "/two-factor/disable", "/two-factor/generate-backup-codes", "/delete-user"]);

type HookCtx = Parameters<Parameters<typeof createAuthMiddleware>[0]>[0];
type Row = Session & Record<string, unknown>;

/**
 * Re-authentication for sensitive actions. A user proves it's them again with
 * their password (`/shield/step-up`) or a second factor (Better Auth's own
 * `/two-factor/verify-*` while signed in), which stamps `session.stepUpAt`.
 * Every attempt counts toward a per-user lock: Better Auth caps second-factor
 * attempts during sign-in only, so without it a stolen session could guess
 * codes forever.
 */
export function stepUp(
  options: StepUpOptions,
  deps: { emit: Emit; store: () => CounterStore; rule: LockRule; tooMany: (until: number) => APIError },
) {
  const maxAge = checkCount("stepUp.maxAge", options.maxAge ?? 300);
  const guarded = new Set(options.paths ?? STEP_UP_PATHS);
  const { emit, rule } = deps;
  const keyOf = (userId: string) => `${userId}:step-up`;
  const headersOf = (ctx: HookCtx) => ctx.request?.headers ?? ctx.headers;

  /** When the session last proved it's the user: its step-up, or its sign-in. */
  const provenAt = (session: Row) =>
    Math.max(new Date((session[STEP_UP_FIELD] as string | Date | null) ?? 0).getTime(), new Date(session.createdAt).getTime());

  /** Whether the session stepped up within `seconds`; reads the stored session when a cached one says no. */
  async function recent(ctx: AuthContext, session: Row, seconds: number) {
    const since = Date.now() - seconds * 1000;
    if (provenAt(session) >= since) return true;
    const stored = (await ctx.internalAdapter.findSession(session.token))?.session as Row | undefined;
    return !!stored && provenAt(stored) >= since;
  }

  async function succeed(ctx: HookCtx, current: { session: Session; user: { id: string } }, method: string) {
    // A first second-factor check turns two-factor on and replaces the session; stamp the new one.
    const session = ctx.context.newSession ?? current;
    const userId = session.user.id;
    await deps.store().reset(keyOf(userId));
    const at = new Date();
    const updated = await ctx.context.internalAdapter.updateSession(session.session.token, { [STEP_UP_FIELD]: at });
    if (!updated) return at;
    // Keep a cookie cache in step with the stored session.
    await setSessionCookie(ctx, { session: { ...session.session, ...updated, [STEP_UP_FIELD]: at } as Session, user: session.user as never });
    await emit(ctx.context, { type: "step_up.success", userId, identifierHash: null, metadata: { method } }, null, headersOf(ctx));
    return at;
  }

  async function fail(ctx: HookCtx, userId: string, method: string) {
    const headers = headersOf(ctx);
    const result = await deps.store().fail(keyOf(userId), rule);
    await emit(ctx.context, { type: "step_up.failure", userId, identifierHash: null, metadata: { method } }, null, headers);
    if (result.justLocked) {
      const metadata = { scope: "step_up", until: new Date(result.lockedUntil).toISOString() };
      await emit(ctx.context, { type: "lockout", userId, identifierHash: null, metadata }, null, headers);
    }
  }

  async function assertUnlocked(userId: string) {
    const until = await deps.store().lockedUntil(keyOf(userId));
    if (until) throw deps.tooMany(until);
  }

  const before: NonNullable<BetterAuthPlugin["hooks"]>["before"] = [
    {
      matcher: (ctx) => !!ctx.path && (guarded.has(ctx.path) || ctx.path in VERIFY_PATHS || PASSWORD_CHECK_PATHS.has(ctx.path)),
      handler: createAuthMiddleware(async (ctx) => {
        const session = await getSessionFromCtx(ctx).catch(() => null);
        // No session: the endpoint refuses it, or it's a sign-in challenge Better Auth caps itself.
        if (!session) return;
        if (ctx.path! in VERIFY_PATHS || PASSWORD_CHECK_PATHS.has(ctx.path!)) await assertUnlocked(session.user.id);
        if (!guarded.has(ctx.path!)) return;
        if (!(await recent(ctx.context, session.session as Row, maxAge))) {
          throw new APIError("FORBIDDEN", ERROR_CODES.STEP_UP_REQUIRED);
        }
      }),
    },
  ];

  const after: NonNullable<BetterAuthPlugin["hooks"]>["after"] = [
    {
      matcher: (ctx) => !!ctx.path && PASSWORD_CHECK_PATHS.has(ctx.path),
      handler: createAuthMiddleware(async (ctx) => {
        const returned = ctx.context.returned;
        if (!(returned instanceof APIError) || returned.body?.code !== "INVALID_PASSWORD") return;
        const session = await getSessionFromCtx(ctx).catch(() => null);
        if (session) await fail(ctx, session.user.id, "password");
      }),
    },
    {
      matcher: (ctx) => !!ctx.path && ctx.path in VERIFY_PATHS,
      handler: createAuthMiddleware(async (ctx) => {
        const session = await getSessionFromCtx(ctx).catch(() => null);
        if (!session) return;
        const method = VERIFY_PATHS[ctx.path!]!;
        const returned = ctx.context.returned;
        if (returned instanceof APIError) {
          if (TWO_FACTOR_FAILURE_CODES.has(String(returned.body?.code))) await fail(ctx, session.user.id, method);
          return;
        }
        if (returned === undefined || (returned instanceof Response && !returned.ok)) return;
        await succeed(ctx, session, method);
      }),
    },
  ];

  /** `/shield/step-up`: checks the account password. */
  async function withPassword(ctx: HookCtx, session: { session: Session; user: { id: string } }, password: string) {
    const userId = session.user.id;
    await assertUnlocked(userId);
    const account = await ctx.context.internalAdapter.findCredentialAccount(userId);
    if (!account?.password) throw new APIError("BAD_REQUEST", ERROR_CODES.NO_PASSWORD);
    if (!(await ctx.context.password.verify({ hash: account.password, password }))) {
      await fail(ctx, userId, "password");
      throw new APIError("UNAUTHORIZED", ERROR_CODES.INVALID_PASSWORD);
    }
    return succeed(ctx, session, "password");
  }

  /** `/shield/require-step-up`: 403 unless the session proved itself within `seconds`. */
  async function require(ctx: AuthContext, session: Session, seconds = maxAge) {
    if (!(await recent(ctx, session as Row, seconds))) throw new APIError("FORBIDDEN", ERROR_CODES.STEP_UP_REQUIRED);
  }

  const fields = {
    [STEP_UP_FIELD]: { type: "date", required: false, input: false },
  } satisfies NonNullable<NonNullable<BetterAuthPlugin["schema"]>[string]>["fields"];

  return { before, after, withPassword, require, fields };
}

const notSet = () => new Error("better-auth-shield: set the `stepUp` option to use step-up");

/** Always registered, so their types don't depend on the options; they throw without `stepUp`. */
export function stepUpEndpoints(get: () => ReturnType<typeof stepUp> | null) {
  return {
    /** Step up with the account password. */
    shieldStepUp: createAuthEndpoint(
      "/shield/step-up",
      { method: "POST", body: z.object({ password: z.string().min(1).max(1024) }), use: [sessionMiddleware] },
      async (ctx) => {
        const stepper = get();
        if (!stepper) throw notSet();
        return ctx.json({ stepUpAt: await stepper.withPassword(ctx, ctx.context.session, ctx.body.password) });
      },
    ),
    /**
     * Server only: throws 403 `STEP_UP_REQUIRED` unless the session in
     * `headers` stepped up (or signed in) within `maxAge` seconds, by default
     * `stepUp.maxAge`. For your own routes; `stepUp.paths` covers Better Auth's.
     */
    shieldRequireStepUp: createAuthEndpoint(
      "/shield/require-step-up",
      {
        method: "POST",
        body: z.object({ maxAge: z.number().int().positive().optional() }).optional(),
        use: [sessionMiddleware],
        metadata: { SERVER_ONLY: true },
      },
      async (ctx) => {
        const stepper = get();
        if (!stepper) throw notSet();
        await stepper.require(ctx.context, ctx.context.session.session, ctx.body?.maxAge);
        return ctx.json({ success: true });
      },
    ),
  };
}
