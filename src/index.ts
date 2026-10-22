import type { AuthContext, BetterAuthPlugin } from "better-auth";
import { z } from "zod";
import { APIError, createAuthEndpoint, createAuthMiddleware, getIP, getSessionFromCtx } from "better-auth/api";
import { COUNTER_MODEL, databaseStore, secondaryStore, type CounterStore, type LockRule } from "./counter.js";
import { ERROR_CODES } from "./error-codes.js";
import {
  FAILURE_CODES,
  SIGN_IN_PATHS,
  TWO_FACTOR_FAILURE_CODES,
  TWO_FACTOR_PATHS,
  hashIdentifier,
  normalizeIdentifier,
} from "./identifier.js";

export { ERROR_CODES } from "./error-codes.js";
export type { ShieldErrorCode } from "./error-codes.js";
export type { LockRule } from "./counter.js";
export { hashIdentifier, normalizeIdentifier } from "./identifier.js";

export const EVENT_MODEL = "securityEvent";

export type SecurityEventType =
  | "sign_in.success"
  | "sign_in.failure"
  | "lockout"
  | "unlock"
  | "two_factor.success"
  | "two_factor.failure";

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
   * still awaits the second factor), lock scope and end for lockouts.
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
   * Where counters live. Defaults to `"secondary-storage"` when Better Auth has
   * a `secondaryStorage` with `increment`, otherwise `"database"` (the
   * `shieldCounter` table).
   */
  storage?: "database" | "secondary-storage";
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

const DAY = 24 * 60 * 60;
const STRICT: LockRule = { maxAttempts: 5, window: 15 * 60, duration: 15 * 60, maxDuration: DAY };
const GLOBAL: LockRule = { maxAttempts: 50, window: 60 * 60, duration: 15 * 60, maxDuration: DAY };
const NO_IP = "no-ip";

function checkRule(name: string, rule: LockRule) {
  for (const [field, value] of Object.entries(rule)) {
    if (!Number.isInteger(value) || value < 1) {
      throw new Error(`better-auth-shield: ${name}.${field} must be a positive integer, got ${String(value)}`);
    }
  }
  return rule;
}

const lockedError = (until: number) => {
  const retryAfter = Math.max(1, Math.ceil((until - Date.now()) / 1000));
  return new APIError("TOO_MANY_REQUESTS", { ...ERROR_CODES.ACCOUNT_LOCKED, retryAfter }, { "Retry-After": String(retryAfter) });
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
  const eventsEnabled = options.events?.enabled !== false;
  const retentionDays = options.events?.retentionDays ?? 90;

  let store: CounterStore;

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
        store = secondaryStore(ctx.options.secondaryStorage, Math.max(strict.maxDuration, global?.maxDuration ?? 0));
      } else {
        store = databaseStore(ctx);
      }
    },
    hooks: {
      before: [
        {
          matcher: (ctx) => !!lockout && !!ctx.path && ctx.path in paths,
          handler: createAuthMiddleware(async (ctx) => {
            const t = await target(ctx);
            if (!t) return;
            const until = Math.max(await store.lockedUntil(t.strictKey), global ? await store.lockedUntil(t.hash) : 0);
            if (until) throw lockedError(until);
          }),
        },
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
          }),
        },
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
       * Server only: delete events older than `retentionDays` and idle counters.
       * Call it from a cron; shield runs no timers of its own.
       */
      shieldCleanup: createAuthEndpoint("/shield/cleanup", { method: "POST", metadata: { SERVER_ONLY: true } }, async (ctx) => {
        const now = Date.now();
        const events = await ctx.context.adapter.deleteMany({
          model: EVENT_MODEL,
          where: [{ field: "createdAt", operator: "lt", value: new Date(now - retentionDays * DAY * 1000) }],
        });
        const longest = Math.max(strict.window, strict.maxDuration, global?.window ?? 0, global?.maxDuration ?? 0) * 1000;
        const counters = await ctx.context.adapter.deleteMany({
          model: COUNTER_MODEL,
          where: [
            { field: "windowStart", operator: "lt", value: now - longest },
            { field: "lockedUntil", operator: "lt", value: now - longest },
          ],
        });
        return ctx.json({ events, counters });
      }),
    },
    schema: {
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
