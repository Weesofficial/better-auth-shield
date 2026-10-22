import type { AuthContext, BetterAuthPlugin } from "better-auth";
import { z } from "zod";
import { APIError, createAuthEndpoint, createAuthMiddleware, getIP, getSessionFromCtx } from "better-auth/api";
import { COUNTER_MODEL, databaseStore, secondaryStore, type CounterStore, type LockRule } from "./counter.js";
import { ERROR_CODES } from "./error-codes.js";
import {
  FAILURE_CODES,
  SEND_PATHS,
  SIGN_IN_PATHS,
  TWO_FACTOR_FAILURE_CODES,
  TWO_FACTOR_PATHS,
  hashIdentifier,
  normalizeIdentifier,
} from "./identifier.js";
import { passwordPolicy, type PasswordOptions } from "./password.js";
import { requiredTwoFactor, type RequiredTwoFactorOptions } from "./required-two-factor.js";

export { ERROR_CODES } from "./error-codes.js";
export type { ShieldErrorCode } from "./error-codes.js";
export type { LockRule } from "./counter.js";
export { SEND_PATHS, SIGN_IN_PATHS } from "./identifier.js";
export { hashIdentifier, normalizeIdentifier } from "./identifier.js";
export { CHANGE_FIELD, HISTORY_MODEL } from "./password.js";
export type { PasswordOptions } from "./password.js";
export { DUE_FIELD } from "./required-two-factor.js";
export type { RequiredTwoFactorOptions } from "./required-two-factor.js";

export const EVENT_MODEL = "securityEvent";

export type SecurityEventType =
  | "sign_in.success"
  | "sign_in.failure"
  | "lockout"
  | "unlock"
  | "two_factor.success"
  | "two_factor.failure"
  | "two_factor.setup_required"
  | "send.limited"
  | "password.changed"
  | "password.reuse_blocked"
  | "password.change_required";

export interface SecurityEvent {
  type: SecurityEventType;
  userId: string | null;
  /** HMAC of the normalized identifier; see `hashIdentifier`. */
  identifierHash: string | null;
  ip: string | null;
  userAgent: string | null;
  /**
   * Endpoint path for sign-in and second-factor events (plus the error `code`
   * of a second-factor failure, and `twoFactorPending` when a correct password
   * still awaits the second factor), lock scope and end for lockouts, `reason`
   * (`max_age` or `manual`) for a required password change, `dueAt` for a
   * two-factor deadline.
   */
  metadata: Record<string, unknown> | null;
  createdAt: Date;
}

export interface ShieldOptions {
  /**
   * Lock an identifier after repeated failed sign-ins, counted per email,
   * username or phone number instead of per IP. `false` turns it off.
   */
  lockout?:
    | false
    | (Partial<LockRule> & {
        /**
         * A second, looser counter on the identifier alone, across every IP. It
         * catches attacks spread over many addresses. The strict counter above is
         * per identifier and IP, so a stranger can't lock a user out from their
         * own network. Defaults to 50 failures per hour. `false` turns it off.
         */
        global?: false | Partial<LockRule>;
        /** Extra sign-in endpoints to watch, as `{ path: bodyField }`. */
        paths?: Record<string, string>;
      });
  /**
   * Cap the codes and links sent to one email or phone number (email OTP,
   * phone OTP, password reset, verification email, magic link), across every
   * IP. Stops inbox flooding and SMS pumping, which the IP rate limiter can't.
   * Defaults to 3 per 10 minutes and 10 per day. `false` turns it off.
   *
   * The request that reaches a limit is still sent; later ones get a 429
   * `SEND_LIMITED` with `Retry-After` until the window has passed, whether or
   * not the account exists.
   */
  sendLimit?:
    | false
    | {
        short?: false | Partial<SendRule>;
        daily?: false | Partial<SendRule>;
        /** Extra sending endpoints to watch, as `{ path: bodyField }`. */
        paths?: Record<string, string>;
      };
  /**
   * Where counters live. Defaults to `"secondary-storage"` when Better Auth has
   * a `secondaryStorage` with `increment`, otherwise `"database"` (the
   * `shieldCounter` table).
   */
  storage?: "database" | "secondary-storage";
  /**
   * Password history, password age and forced changes. Off unless set; `{}`
   * blocks reuse of the last 5 passwords. Adds the `passwordHistory` table and
   * `user.passwordChangeRequired`. Leave length rules to Better Auth's
   * `minPasswordLength` and breach checks to its `haveIBeenPwned` plugin.
   */
  password?: PasswordOptions;
  /**
   * Make two-factor mandatory for everyone (`required: true`) or for the users
   * a function picks, e.g. `(user) => user.role === "admin"`. Needs Better
   * Auth's `twoFactor()` plugin. Adds `user.twoFactorDueAt`.
   */
  twoFactor?: RequiredTwoFactorOptions;
  /** The `securityEvent` table. `false` stops writing it; `onEvent` still runs. */
  events?: {
    enabled?: boolean;
    /** Days `cleanup` keeps events for. Defaults to 90. */
    retentionDays?: number;
    /**
     * Called for every event, after it is stored. `identifier` is the
     * normalized email, username or phone number, which the table never
     * stores. Errors are logged and never fail the request.
     */
    onEvent?: (event: SecurityEvent, info: { identifier: string | null }) => void | Promise<void>;
  };
}

export interface SendRule {
  /** Sends allowed per window. */
  max: number;
  /** Window in seconds; once the limit is hit, sending stops this long. */
  window: number;
}

const DAY = 24 * 60 * 60;
const STRICT: LockRule = { maxAttempts: 5, window: 15 * 60, duration: 15 * 60, maxDuration: DAY };
const GLOBAL: LockRule = { maxAttempts: 50, window: 60 * 60, duration: 15 * 60, maxDuration: DAY };
const SEND_SHORT: SendRule = { max: 3, window: 10 * 60 };
const SEND_DAILY: SendRule = { max: 10, window: DAY };
const NO_IP = "no-ip";

function checkRule(name: string, rule: LockRule) {
  for (const [field, value] of Object.entries(rule)) {
    if (!Number.isInteger(value) || value < 1) {
      throw new Error(`better-auth-shield: ${name}.${field} must be a positive integer, got ${String(value)}`);
    }
  }
  return rule;
}

/** A send limit is a lock that lasts one window and never escalates. */
const sendRule = (name: string, rule: SendRule): LockRule =>
  checkRule(name, { maxAttempts: rule.max, window: rule.window, duration: rule.window, maxDuration: rule.window });

const tooMany = (error: (typeof ERROR_CODES)[keyof typeof ERROR_CODES], until: number) => {
  const retryAfter = Math.max(1, Math.ceil((until - Date.now()) / 1000));
  return new APIError("TOO_MANY_REQUESTS", { ...error, retryAfter }, { "Retry-After": String(retryAfter) });
};

/**
 * Account security for Better Auth: lockout per identifier and a security
 * event log in your own database.
 */
export const shield = (options: ShieldOptions = {}) => {
  const lockout = options.lockout === false ? null : (options.lockout ?? {});
  const { global: globalOption, paths: extraPaths, ...strictOption } = lockout ?? {};
  const strict = checkRule("lockout", { ...STRICT, ...strictOption });
  const global = globalOption === false ? null : checkRule("lockout.global", { ...GLOBAL, ...globalOption });
  const paths: Record<string, string> = { ...SIGN_IN_PATHS, ...extraPaths };
  const send = options.sendLimit === false ? null : (options.sendLimit ?? {});
  const sendRules = send
    ? (
        [
          ["short", send.short, SEND_SHORT],
          ["daily", send.daily, SEND_DAILY],
        ] as const
      ).flatMap(([scope, option, base]) =>
        option === false ? [] : [{ scope, rule: sendRule(`sendLimit.${scope}`, { ...base, ...option }) }],
      )
    : [];
  const sendPaths: Record<string, string> = send ? { ...SEND_PATHS, ...send.paths } : {};
  /** The longest any counter or lock can matter, in seconds. */
  const longest = Math.max(
    ...[strict, global, ...sendRules.map((s) => s.rule)].flatMap((rule) => (rule ? [rule.window, rule.maxDuration] : [])),
  );
  const eventsEnabled = options.events?.enabled !== false;
  const retentionDays = options.events?.retentionDays ?? 90;

  let store: CounterStore;
  const policy = options.password ? passwordPolicy(options.password, emit) : null;
  const mandatory = options.twoFactor ? requiredTwoFactor(options.twoFactor, emit) : null;

  async function emit(
    ctx: AuthContext,
    event: Omit<SecurityEvent, "createdAt" | "userId" | "ip" | "userAgent"> & Partial<SecurityEvent>,
    identifier: string | null,
    headers: Headers | undefined,
  ) {
    const full: SecurityEvent = {
      userId: null,
      ip: headers ? getIP(headers, ctx.options) : null,
      userAgent: headers?.get("user-agent")?.slice(0, 512) ?? null,
      createdAt: new Date(),
      ...event,
    };
    const task = (async () => {
      if (eventsEnabled) {
        await ctx.adapter.create({
          model: EVENT_MODEL,
          data: { ...full, metadata: full.metadata ? JSON.stringify(full.metadata) : null },
        });
      }
      await options.events?.onEvent?.(full, { identifier });
    })().catch((error) => ctx.logger.error("better-auth-shield: failed to record a security event", error));
    await ctx.runInBackgroundOrAwait(task);
  }

  /** The counter keys and identifier of a watched request, or null when it names none. */
  async function target(ctx: { path?: string; body?: unknown; request?: Request; headers?: Headers; context: AuthContext }) {
    const field = ctx.path ? paths[ctx.path] : undefined;
    if (!field || !lockout) return null;
    const identifier = normalizeIdentifier(field, (ctx.body as Record<string, unknown> | undefined)?.[field]);
    if (!identifier) return null;
    const hash = await hashIdentifier(ctx.context.secret, identifier);
    const headers = ctx.request?.headers ?? ctx.headers;
    const ip = (headers && getIP(headers, ctx.context.options)) || NO_IP;
    return { identifier, hash, strictKey: `${hash}:${ip}`, headers };
  }

  return {
    id: "shield",
    init(ctx) {
      const storage = options.storage ?? (ctx.options.secondaryStorage?.increment ? "secondary-storage" : "database");
      if (storage === "secondary-storage") {
        if (!ctx.options.secondaryStorage?.increment) {
          throw new Error(
            "better-auth-shield: storage \"secondary-storage\" needs a Better Auth `secondaryStorage` with an atomic `increment`.",
          );
        }
        store = secondaryStore(ctx.options.secondaryStorage, longest);
      } else {
        store = databaseStore(ctx);
      }
      mandatory?.init(ctx);
      if (policy) return { options: { databaseHooks: policy.databaseHooks } };
    },
    hooks: {
      before: [
        {
          matcher: (ctx) => !!lockout && !!ctx.path && ctx.path in paths,
          handler: createAuthMiddleware(async (ctx) => {
            const t = await target(ctx);
            if (!t) return;
            const until = Math.max(await store.lockedUntil(t.strictKey), global ? await store.lockedUntil(t.hash) : 0);
            if (until) throw tooMany(ERROR_CODES.ACCOUNT_LOCKED, until);
          }),
        },
        {
          matcher: (ctx) => !!ctx.path && ctx.path in sendPaths && sendRules.length > 0,
          handler: createAuthMiddleware(async (ctx) => {
            const field = sendPaths[ctx.path!]!;
            const identifier = normalizeIdentifier(field, (ctx.body as Record<string, unknown> | undefined)?.[field]);
            if (!identifier) return;
            const hash = await hashIdentifier(ctx.context.secret, identifier);
            const headers = ctx.request?.headers ?? ctx.headers;
            // A refused request counts toward no window, so waiting out the short one is enough.
            const keys = sendRules.map(({ scope }) => `${hash}:send-${scope}`);
            const until = Math.max(...(await Promise.all(keys.map((key) => store.lockedUntil(key)))));
            if (until) throw tooMany(ERROR_CODES.SEND_LIMITED, until);
            // Counted before sending, so concurrent requests can't all slip under the limit.
            for (const { scope, rule } of sendRules) {
              const result = await store.fail(`${hash}:send-${scope}`, rule);
              if (result.justLocked) {
                const metadata = { path: ctx.path, scope, until: new Date(result.lockedUntil).toISOString() };
                await emit(ctx.context, { type: "send.limited", identifierHash: hash, metadata }, identifier, headers);
              } else if (result.lockedUntil) {
                throw tooMany(ERROR_CODES.SEND_LIMITED, result.lockedUntil);
              }
            }
          }),
        },
        ...(policy?.before ?? []),
        ...(mandatory?.before ?? []),
      ],
      after: [
        {
          matcher: (ctx) => !!ctx.path && ctx.path in paths,
          handler: createAuthMiddleware(async (ctx) => {
            const t = await target(ctx);
            if (!t) return;
            const returned = ctx.context.returned;
            const path = ctx.path;

            if (returned instanceof APIError) {
              if (!FAILURE_CODES.has(String(returned.body?.code))) return;
              const local = await store.fail(t.strictKey, strict);
              const wide = global ? await store.fail(t.hash, global) : null;
              await emit(ctx.context, { type: "sign_in.failure", identifierHash: t.hash, metadata: { path } }, t.identifier, t.headers);
              for (const [scope, result] of [["ip", local], ["global", wide]] as const) {
                if (result?.justLocked) {
                  await emit(
                    ctx.context,
                    { type: "lockout", identifierHash: t.hash, metadata: { scope, until: new Date(result.lockedUntil).toISOString() } },
                    t.identifier,
                    t.headers,
                  );
                }
              }
              return;
            }
            if (returned === undefined || (returned instanceof Response && !returned.ok)) return;

            await store.reset(t.strictKey);
            if (global) await store.reset(t.hash);
            const body = returned as { user?: { id?: string }; twoFactorRedirect?: boolean } | null;
            const user = body?.user ?? ctx.context.newSession?.user;
            const metadata = body?.twoFactorRedirect ? { path, twoFactorPending: true } : { path };
            await emit(
              ctx.context,
              { type: "sign_in.success", userId: user?.id ?? null, identifierHash: t.hash, metadata },
              t.identifier,
              t.headers,
            );
            if (policy && user?.id) await policy.onSignIn(ctx, user.id);
          }),
        },
        {
          matcher: (ctx) => !!ctx.path && TWO_FACTOR_PATHS.has(ctx.path),
          handler: createAuthMiddleware(async (ctx) => {
            const returned = ctx.context.returned;
            const headers = ctx.request?.headers ?? ctx.headers;
            const path = ctx.path;
            if (returned instanceof APIError) {
              const code = String(returned.body?.code);
              if (!TWO_FACTOR_FAILURE_CODES.has(code)) return;
              // The user is behind the signed two_factor cookie during sign-in, or the session otherwise.
              let userId = (await getSessionFromCtx(ctx).catch(() => null))?.user.id ?? null;
              if (!userId) {
                const token = await ctx.getSignedCookie(ctx.context.createAuthCookie("two_factor").name, ctx.context.secret);
                userId = (token && (await ctx.context.internalAdapter.findVerificationValue(token))?.value) || null;
              }
              await emit(ctx.context, { type: "two_factor.failure", userId, identifierHash: null, metadata: { path, code } }, null, headers);
              // Better Auth refuses every attempt while its lock holds, so only the failure that set it sees it.
              const row = userId
                ? await ctx.context.adapter.findOne<{ lockedUntil?: Date | string | null }>({
                    model: "twoFactor",
                    where: [{ field: "userId", value: userId }],
                  })
                : null;
              const until = row?.lockedUntil ? new Date(row.lockedUntil).getTime() : 0;
              if (until > Date.now()) {
                await emit(
                  ctx.context,
                  { type: "lockout", userId, identifierHash: null, metadata: { scope: "two_factor", until: new Date(until).toISOString() } },
                  null,
                  headers,
                );
              }
              return;
            }
            if (returned === undefined || (returned instanceof Response && !returned.ok)) return;
            const userId = (returned as { user?: { id?: string } } | null)?.user?.id ?? ctx.context.newSession?.user.id ?? null;
            await emit(ctx.context, { type: "two_factor.success", userId, identifierHash: null, metadata: { path } }, null, headers);
            if (policy && userId) await policy.onSignIn(ctx, userId);
          }),
        },
        ...(policy?.after ?? []),
        ...(mandatory?.after ?? []),
      ],
    },
    endpoints: {
      /** Server only: lift every lock on an identifier, e.g. from your support tooling. */
      shieldUnlock: createAuthEndpoint(
        "/shield/unlock",
        {
          method: "POST",
          body: z.object({ identifier: z.string().min(1).max(320) }),
          metadata: { SERVER_ONLY: true },
        },
        async (ctx) => {
          const raw = ctx.body.identifier;
          // A phone number may have been typed with separators the sign-in form stripped.
          const forms = new Set([normalizeIdentifier("email", raw)]);
          if (/^[+\d\s().-]+$/.test(raw)) forms.add(normalizeIdentifier("phoneNumber", raw));
          for (const identifier of forms) {
            if (!identifier) continue;
            const hash = await hashIdentifier(ctx.context.secret, identifier);
            await store.unlock(hash);
            await emit(ctx.context, { type: "unlock", identifierHash: hash, metadata: null }, identifier, ctx.request?.headers ?? ctx.headers);
          }
          return ctx.json({ success: true });
        },
      ),
      /**
       * Server only: make a user change their password before doing anything
       * else, e.g. after a breach. Needs the `password` option.
       */
      shieldRequirePasswordChange: createAuthEndpoint(
        "/shield/require-password-change",
        {
          method: "POST",
          body: z.object({ userId: z.string().min(1) }),
          metadata: { SERVER_ONLY: true },
        },
        async (ctx) => {
          if (!policy) throw new Error("better-auth-shield: set the `password` option to use shieldRequirePasswordChange");
          await policy.setRequired(ctx.context, ctx.body.userId, "manual", ctx.request?.headers ?? ctx.headers);
          return ctx.json({ success: true });
        },
      ),
      /**
       * Server only: delete events older than `retentionDays` and idle counters.
       * Call it from a cron; shield runs no timers of its own.
       */
      shieldCleanup: createAuthEndpoint("/shield/cleanup", { method: "POST", metadata: { SERVER_ONLY: true } }, async (ctx) => {
        const now = Date.now();
        const events = await ctx.context.adapter.deleteMany({
          model: EVENT_MODEL,
          where: [{ field: "createdAt", operator: "lt", value: new Date(now - retentionDays * DAY * 1000) }],
        });
        const idle = now - longest * 1000;
        const counters = await ctx.context.adapter.deleteMany({
          model: COUNTER_MODEL,
          where: [
            { field: "windowStart", operator: "lt", value: idle },
            { field: "lockedUntil", operator: "lt", value: idle },
          ],
        });
        return ctx.json({ events, counters });
      }),
    },
    schema: {
      ...policy?.schema,
      user: { fields: { ...policy?.schema.user.fields, ...mandatory?.fields } },
      [COUNTER_MODEL]: {
        fields: {
          key: { type: "string", unique: true, required: true },
          count: { type: "number", required: true },
          windowStart: { type: "number", bigint: true, required: true },
          lockedUntil: { type: "number", bigint: true, required: true },
          level: { type: "number", required: true },
        },
      },
      [EVENT_MODEL]: {
        fields: {
          type: { type: "string", required: true, index: true },
          userId: { type: "string", required: false, index: true },
          identifierHash: { type: "string", required: false, index: true },
          ip: { type: "string", required: false },
          userAgent: { type: "string", required: false },
          metadata: { type: "string", required: false },
          createdAt: { type: "date", required: true, index: true },
        },
      },
    },
    $ERROR_CODES: ERROR_CODES,
  } satisfies BetterAuthPlugin;
};
