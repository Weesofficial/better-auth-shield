import type { AuthContext, BetterAuthPlugin, User } from "better-auth";
import { APIError, createAuthMiddleware, getSessionFromCtx } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import { ERROR_CODES } from "./error-codes.js";
import { OPEN_PATHS } from "./identifier.js";
import { checkCount, type Emit } from "./password.js";

export const DUE_FIELD = "twoFactorDueAt";

export interface RequiredTwoFactorOptions {
  /** Who must turn on two-factor: everyone, or the users this returns true for. */
  required: true | ((user: User & Record<string, unknown>) => boolean | Promise<boolean>);
  /**
   * Days a covered user can keep using the app before setting it up, counted
   * from the first time shield sees them without it. Defaults to 7; `0` blocks
   * at once.
   */
  graceDays?: number;
  /** Extra endpoints a user past the deadline can still call. */
  allow?: string[];
}

type Row = User & Record<string, unknown>;

const DISABLE_PATH = "/two-factor/disable";
const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * Two-factor for some or all users. A covered user without it gets a deadline
 * (`user.twoFactorDueAt`); after it, Better Auth's endpoints other than sign-in,
 * sign-out and two-factor setup answer 403 `TWO_FACTOR_SETUP_REQUIRED`, and a
 * covered user can never turn two-factor off.
 */
export function requiredTwoFactor(options: RequiredTwoFactorOptions, emit: Emit) {
  const graceDays = checkCount("twoFactor.graceDays", options.graceDays ?? 7);
  const allowed = new Set([...OPEN_PATHS, ...(options.allow ?? [])]);
  const covers = async (user: Row) => options.required === true || (await options.required(user));
  const isOpen = (path: string) => allowed.has(path) || (path.startsWith("/two-factor/") && path !== DISABLE_PATH);

  function init(ctx: AuthContext) {
    if (!ctx.options.plugins?.some((plugin) => plugin.id === "two-factor")) {
      throw new Error("better-auth-shield: the `twoFactor` option needs Better Auth's twoFactor() plugin.");
    }
  }

  /** The user's deadline, set now if they are covered, without two-factor, and have none yet. */
  async function deadline(ctx: AuthContext, user: Row, headers: Headers | undefined) {
    if (user.twoFactorEnabled || !(await covers(user))) return null;
    if (user[DUE_FIELD]) return new Date(user[DUE_FIELD] as string | Date);
    // A cached session may predate the deadline; never restart the grace period from it.
    const stored = (await ctx.internalAdapter.findUserById(user.id)) as Row | null;
    if (!stored || stored.twoFactorEnabled) return null;
    if (stored[DUE_FIELD]) return new Date(stored[DUE_FIELD] as string | Date);
    const due = new Date(Date.now() + graceDays * DAY_MS);
    await ctx.internalAdapter.updateUser(user.id, { [DUE_FIELD]: due });
    await emit(ctx, { type: "two_factor.setup_required", userId: user.id, identifierHash: null, metadata: { dueAt: due.toISOString() } }, null, headers);
    return due;
  }

  const before: NonNullable<BetterAuthPlugin["hooks"]>["before"] = [
    {
      matcher: (ctx) => !!ctx.path && !isOpen(ctx.path),
      handler: createAuthMiddleware(async (ctx) => {
        const session = await getSessionFromCtx(ctx).catch(() => null);
        if (!session) return;
        // A cookie cache serves the user as it was when cached: a role granted or two-factor
        // turned off since would go unseen until it expires. Decide on the stored user then.
        const stored = ctx.path === DISABLE_PATH || !!ctx.context.options.session?.cookieCache?.enabled;
        const user = stored ? ((await ctx.context.internalAdapter.findUserById(session.user.id)) as Row | null) : (session.user as Row);
        if (!user) return;
        if (ctx.path === DISABLE_PATH) {
          if (await covers(user)) throw new APIError("FORBIDDEN", ERROR_CODES.TWO_FACTOR_REQUIRED);
          return;
        }
        const due = await deadline(ctx.context, user, ctx.request?.headers ?? ctx.headers);
        if (!due || due.getTime() > Date.now()) return;
        // A cached session can miss a two-factor setup that just happened.
        const fresh = stored ? user : ((await ctx.context.internalAdapter.findUserById(user.id)) as Row | null);
        if (fresh && !fresh.twoFactorEnabled && (await covers(fresh))) {
          throw new APIError("FORBIDDEN", ERROR_CODES.TWO_FACTOR_SETUP_REQUIRED);
        }
      }),
    },
  ];

  const after: NonNullable<BetterAuthPlugin["hooks"]>["after"] = [
    {
      // Any new session (sign-in, sign-up, social, magic link) carries the deadline from the start.
      matcher: () => true,
      handler: createAuthMiddleware(async (ctx) => {
        const created = ctx.context.newSession;
        if (!created) return;
        const user = created.user as Row;
        const had = user[DUE_FIELD];
        const due = await deadline(ctx.context, user, ctx.request?.headers ?? ctx.headers);
        if (due && !had) {
          await setSessionCookie(ctx, { session: created.session, user: { ...created.user, [DUE_FIELD]: due } as typeof created.user });
        }
      }),
    },
  ];

  const fields = {
    [DUE_FIELD]: { type: "date", required: false, input: false },
  } satisfies NonNullable<NonNullable<BetterAuthPlugin["schema"]>[string]>["fields"];

  return { init, before, after, fields };
}
