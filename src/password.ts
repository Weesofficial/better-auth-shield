import { defineRequestState, getCurrentAdapter } from "@better-auth/core/context";
import type { AuthContext, BetterAuthOptions, BetterAuthPlugin } from "better-auth";
import { APIError, createAuthMiddleware, getSessionFromCtx } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import { ERROR_CODES } from "./error-codes.js";
import { OPEN_PATHS } from "./identifier.js";
import type { SecurityEvent } from "./index.js";

export const HISTORY_MODEL = "passwordHistory";
export const CHANGE_FIELD = "passwordChangeRequired";

export interface PasswordOptions {
  /**
   * How many passwords can't be used again, counting the current one.
   * Defaults to 5. `1` only blocks the current password; `0` turns the check off.
   */
  history?: number;
  /**
   * Days after which a password must be changed; checked at sign-in. Defaults
   * to 0, no expiry: NIST SP 800-63B advises against forced rotation.
   */
  maxAgeDays?: number;
  /** Extra endpoints a user who must change their password can still call. */
  allow?: string[];
}

type EndpointCtx = {
  path?: string;
  body?: any;
  context: AuthContext & { session?: { user: { id: string } } | null };
};

export type Emit = (
  ctx: AuthContext,
  event: Pick<SecurityEvent, "type" | "metadata"> & { userId: string | null; identifierHash: null },
  identifier: null,
  headers: Headers | undefined,
) => Promise<void>;

/** What the account hook learnt about the password being set, for the after hook. */
const pending = defineRequestState<{ userId: string; previous: string | null; reused: boolean } | null>(() => null);

const ADMIN_PATH = "/admin/set-user-password";

/** Endpoints that set a password: the body field holding it, and whose password it is. */
const PASSWORD_PATHS: Record<string, { field: string; user: (ctx: EndpointCtx) => Promise<string | null | undefined> }> = {
  "/change-password": { field: "newPassword", user: async (ctx) => ctx.context.session?.user.id },
  "/set-password": { field: "newPassword", user: async (ctx) => ctx.context.session?.user.id },
  // Checked in a before hook instead, see there.
  "/reset-password": { field: "newPassword", user: async () => null },
  [ADMIN_PATH]: { field: "newPassword", user: async (ctx) => ctx.body?.userId },
  "/email-otp/reset-password": {
    field: "password",
    user: async (ctx) => (await ctx.context.internalAdapter.findUserByEmail(String(ctx.body?.email).toLowerCase()))?.user.id,
  },
  "/phone-number/reset-password": {
    field: "newPassword",
    user: async (ctx) =>
      (
        await (await getCurrentAdapter(ctx.context.adapter)).findOne<{ id: string }>({
          model: "user",
          where: [{ field: "phoneNumber", value: String(ctx.body?.phoneNumber) }],
        })
      )?.id,
  },
};


export function checkCount(name: string, value: number) {
  if (!Number.isInteger(value) || value < 0) {
    throw new Error(`better-auth-shield: ${name} must be a non-negative integer, got ${String(value)}`);
  }
  return value;
}

/**
 * Password history, password age and forced changes. The reuse check runs in
 * a database hook on the credential account, so it only sees a password after
 * Better Auth has accepted the token, code or current password: a wrong code
 * never tells anyone whether a guess was an old password.
 */
export function passwordPolicy(options: PasswordOptions, emit: Emit) {
  const history = checkCount("password.history", options.history ?? 5);
  const maxAgeDays = checkCount("password.maxAgeDays", options.maxAgeDays ?? 0);
  const allowed = new Set([...OPEN_PATHS, "/set-password", ...(options.allow ?? [])]);

  async function setRequired(ctx: AuthContext, userId: string, reason: string, headers: Headers | undefined) {
    await ctx.internalAdapter.updateUser(userId, { [CHANGE_FIELD]: true });
    await emit(ctx, { type: "password.change_required", userId, identifierHash: null, metadata: { reason } }, null, headers);
  }

  /** Whether `plain` is the current password or a stored old one. */
  async function check(ctx: AuthContext, userId: string, plain: string) {
    // Inside Better Auth's transaction, when there is one.
    const adapter = await getCurrentAdapter(ctx.adapter);
    const account = await adapter.findOne<{ password?: string | null }>({
      model: "account",
      where: [
        { field: "userId", value: userId },
        { field: "providerId", value: "credential" },
      ],
    });
    const previous = account?.password ?? null;
    const older =
      history > 1
        ? await adapter.findMany<{ hash: string }>({
            model: HISTORY_MODEL,
            where: [{ field: "userId", value: userId }],
            sortBy: { field: "createdAt", direction: "desc" },
            limit: history - 1,
          })
        : [];
    const hashes = history > 0 ? [previous, ...older.map((row) => row.hash)].filter((hash): hash is string => !!hash) : [];
    const matches = await Promise.all(hashes.map((hash) => ctx.password.verify({ hash, password: plain })));
    const reused = matches.some(Boolean);
    await pending.set({ userId, previous, reused });
    return reused;
  }

  const databaseHooks: BetterAuthOptions["databaseHooks"] = {
    account: {
      create: {
        // A first password, e.g. a social-only user resetting one: nothing to compare, but it still counts as a change.
        before: async (data, ctx) => {
          const spec = ctx?.path ? PASSWORD_PATHS[ctx.path] : undefined;
          if (spec && data.providerId === "credential" && data.password) {
            await pending.set({ userId: data.userId, previous: null, reused: false });
          }
        },
      },
      update: {
        before: async (data, ctx) => {
          const spec = ctx?.path ? PASSWORD_PATHS[ctx.path] : undefined;
          const plain = ctx?.body?.[spec?.field ?? ""];
          if (!ctx || !spec || typeof data.password !== "string" || typeof plain !== "string") return;
          const userId = await spec.user(ctx as unknown as EndpointCtx);
          if (userId && (await check(ctx.context, userId, plain))) {
            throw new APIError("BAD_REQUEST", ERROR_CODES.PASSWORD_REUSED);
          }
        },
      },
    },
  };

  const before: NonNullable<BetterAuthPlugin["hooks"]>["before"] = [
    {
      // Better Auth spends the token before writing the password, and a token in
      // secondary storage can't be put back, so a refusal from the account hook
      // would burn the link. Whoever holds a valid token may set any password,
      // so checking here first tells them nothing.
      matcher: (ctx) => ctx.path === "/reset-password",
      handler: createAuthMiddleware(async (ctx) => {
        // `||` like Better Auth: an empty body token falls back to the query one.
        const token = ctx.body?.token || ctx.query?.token;
        const plain = ctx.body?.newPassword;
        if (typeof token !== "string" || typeof plain !== "string") return;
        const verification = await ctx.context.internalAdapter.findVerificationValue(`reset-password:${token}`);
        if (!verification || new Date(verification.expiresAt) <= new Date()) return;
        const userId = verification.value;
        if (await check(ctx.context, userId, plain)) {
          // After hooks don't run when a before hook throws.
          const metadata = { path: ctx.path };
          await emit(ctx.context, { type: "password.reuse_blocked", userId, identifierHash: null, metadata }, null, ctx.request?.headers ?? ctx.headers);
          throw new APIError("BAD_REQUEST", ERROR_CODES.PASSWORD_REUSED);
        }
      }),
    },
    {
      matcher: (ctx) => !!ctx.path && !allowed.has(ctx.path),
      handler: createAuthMiddleware(async (ctx) => {
        const session = await getSessionFromCtx(ctx).catch(() => null);
        if (!(session?.user as Record<string, unknown> | undefined)?.[CHANGE_FIELD]) return;
        // A cached session can still carry a flag the user has since cleared.
        const user = await ctx.context.internalAdapter.findUserById(session!.user.id);
        if ((user as Record<string, unknown> | null)?.[CHANGE_FIELD]) {
          throw new APIError("FORBIDDEN", ERROR_CODES.PASSWORD_CHANGE_REQUIRED);
        }
      }),
    },
  ];

  const after: NonNullable<BetterAuthPlugin["hooks"]>["after"] = [
    {
      matcher: (ctx) => !!ctx.path && ctx.path in PASSWORD_PATHS,
      handler: createAuthMiddleware(async (ctx) => {
        const change = await pending.get();
        if (!change) return;
        const { userId, previous } = change;
        const headers = ctx.request?.headers ?? ctx.headers;
        const returned = ctx.context.returned;
        if (returned instanceof APIError) {
          if (change.reused && returned.body?.code === ERROR_CODES.PASSWORD_REUSED.code) {
            await emit(ctx.context, { type: "password.reuse_blocked", userId, identifierHash: null, metadata: { path: ctx.path } }, null, headers);
          }
          return;
        }
        if (returned === undefined || (returned instanceof Response && !returned.ok)) return;

        if (previous && history > 1) {
          const adapter = ctx.context.adapter;
          await adapter.create({ model: HISTORY_MODEL, data: { userId, hash: previous, createdAt: new Date() } });
          const rows = await adapter.findMany<{ id: string }>({
            model: HISTORY_MODEL,
            where: [{ field: "userId", value: userId }],
            sortBy: { field: "createdAt", direction: "desc" },
          });
          const extra = rows.slice(history - 1).map((row) => row.id);
          if (extra.length) await adapter.deleteMany({ model: HISTORY_MODEL, where: [{ field: "id", operator: "in", value: extra }] });
        }
        // An admin setting a password, often a temporary one, doesn't satisfy a required change.
        if (ctx.path !== ADMIN_PATH) {
          const user = await ctx.context.internalAdapter.findUserById(userId);
          if ((user as Record<string, unknown> | null)?.[CHANGE_FIELD]) {
            await ctx.context.internalAdapter.updateUser(userId, { [CHANGE_FIELD]: false });
          }
        }
        await emit(ctx.context, { type: "password.changed", userId, identifierHash: null, metadata: { path: ctx.path } }, null, headers);
      }),
    },
  ];

  /** Called by the sign-in hook after a correct password: flags passwords older than `maxAgeDays`. */
  async function onSignIn(ctx: Parameters<Parameters<typeof createAuthMiddleware>[0]>[0], userId: string) {
    if (!maxAgeDays) return;
    const account = await ctx.context.internalAdapter.findCredentialAccount(userId);
    if (!account?.password) return;
    const setAt = new Date(account.updatedAt ?? account.createdAt).getTime();
    if (Date.now() - setAt <= maxAgeDays * 24 * 60 * 60 * 1000) return;
    const user = await ctx.context.internalAdapter.findUserById(userId);
    if (!user || (user as Record<string, unknown>)[CHANGE_FIELD]) return;
    await setRequired(ctx.context, userId, "max_age", ctx.request?.headers ?? ctx.headers);
    // The session cookie was written with the old flag; write it again so a cookie cache can't skip the change.
    const fresh = ctx.context.newSession;
    if (fresh) await setSessionCookie(ctx, { session: fresh.session, user: { ...fresh.user, [CHANGE_FIELD]: true } as typeof fresh.user });
  }

  const schema = {
    user: {
      fields: {
        [CHANGE_FIELD]: { type: "boolean", required: false, defaultValue: false, input: false },
      },
    },
    [HISTORY_MODEL]: {
      fields: {
        userId: { type: "string", required: true, index: true, references: { model: "user", field: "id", onDelete: "cascade" } },
        hash: { type: "string", required: true, returned: false },
        createdAt: { type: "date", required: true },
      },
    },
  } satisfies BetterAuthPlugin["schema"];

  return { databaseHooks, before, after, onSignIn, setRequired, schema };
}
