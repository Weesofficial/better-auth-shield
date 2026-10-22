import assert from "node:assert/strict";
import { afterEach, describe, it, mock } from "node:test";
import { admin, twoFactor, username } from "better-auth/plugins";
import { shield, type ShieldOptions } from "../src/index.js";
import { HAS_SQLITE, EMAIL, PASSWORD, cookiesOf, memoryStorage, post, setup, signIn } from "./helpers.js";

const backends = {
  memory: () => ({}),
  sqlite: () => ({ database: "sqlite" as const }),
  "secondary-storage": () => ({ auth: { secondaryStorage: memoryStorage() } }),
};

const DAY = 24 * 60 * 60 * 1000;

async function app(backend: keyof typeof backends, required: NonNullable<ShieldOptions["twoFactor"]>, options: object = {}) {
  const extra = backends[backend]();
  const { auth } = await setup({
    ...extra,
    auth: { ...(extra as { auth?: object }).auth, ...options },
    plugins: [username(), admin(), twoFactor({ skipVerificationOnEnable: true }), shield({ twoFactor: required, sendLimit: false })],
  });
  const signUp = async (email: string, name: string) => {
    const res = await post(auth, "/sign-up/email", { email, password: PASSWORD, name, username: name });
    return { user: ((await res.json()) as { user: { id: string } }).user, cookie: cookiesOf(res) };
  };
  const events = async () => {
    const { adapter } = await auth.$context;
    const rows = await adapter.findMany<{ type: string }>({ model: "securityEvent", sortBy: { field: "createdAt", direction: "asc" } });
    return rows.map((r) => r.type).filter((t) => t === "two_factor.setup_required");
  };
  const update = (cookie: string) => post(auth, "/update-user", { name: "Ada L" }, undefined, cookie);
  // Turning two-factor on replaces the session; returns the new cookie.
  const enable = async (cookie: string) => {
    const res = await post(auth, "/two-factor/enable", { password: PASSWORD }, undefined, cookie);
    assert.equal(res.status, 200);
    return cookiesOf(res) || cookie;
  };
  return { auth, signUp, events, update, enable };
}

const codeOf = async (res: Response) => ((await res.json()) as { code?: string }).code;

for (const backend of Object.keys(backends) as (keyof typeof backends)[]) {
  if (backend === "sqlite" && !HAS_SQLITE) continue;
  describe(`required two-factor (${backend})`, () => {
    afterEach(() => mock.timers.reset());

    it("gives a grace period, then allows only two-factor setup", async () => {
      mock.timers.enable({ apis: ["Date"], now: Date.now() });
      const { auth, signUp, events, update, enable } = await app(backend, { required: true, graceDays: 3 });
      const { cookie } = await signUp(EMAIL, "ada_l");
      const session = await auth.api.getSession({ headers: new Headers({ cookie }) });
      const due = new Date((session?.user as Record<string, unknown>).twoFactorDueAt as string).getTime();
      assert.equal(due, Date.now() + 3 * DAY);
      assert.equal((await update(cookie)).status, 200);

      mock.timers.tick(4 * DAY);
      const late = cookiesOf(await signIn(auth, EMAIL, PASSWORD));
      const blocked = await update(late);
      assert.equal(blocked.status, 403);
      assert.equal(await codeOf(blocked), "TWO_FACTOR_SETUP_REQUIRED");
      assert.ok(await auth.api.getSession({ headers: new Headers({ cookie: late }) }));
      assert.equal((await update(await enable(late))).status, 200);
      // Signing in again never restarted the deadline.
      assert.deepEqual(await events(), ["two_factor.setup_required"]);
    });

    it("blocks at once with graceDays: 0", async () => {
      const { signUp, update, enable } = await app(backend, { required: true, graceDays: 0 });
      const { cookie } = await signUp(EMAIL, "ada_l");
      assert.equal(await codeOf(await update(cookie)), "TWO_FACTOR_SETUP_REQUIRED");
      assert.equal((await update(await enable(cookie))).status, 200);
    });

    it("covers only the users `required` picks, and they can't turn it off", async () => {
      const { auth, signUp, update, enable } = await app(backend, { required: (user) => user.role === "admin", graceDays: 0 });
      const ada = await signUp(EMAIL, "ada_l");
      const root = await signUp("root@example.com", "root");
      const { adapter } = await auth.$context;
      await adapter.update({ model: "user", where: [{ field: "id", value: root.user.id }], update: { role: "admin" } });
      const rootCookie = cookiesOf(await signIn(auth, "root@example.com", PASSWORD));

      assert.equal((await update(ada.cookie)).status, 200);
      assert.equal(await codeOf(await update(rootCookie)), "TWO_FACTOR_SETUP_REQUIRED");

      const off = await post(auth, "/two-factor/disable", { password: PASSWORD }, undefined, await enable(rootCookie));
      assert.equal(off.status, 403);
      assert.equal(await codeOf(off), "TWO_FACTOR_REQUIRED");

      assert.equal((await post(auth, "/two-factor/disable", { password: PASSWORD }, undefined, await enable(ada.cookie))).status, 200);
    });

    it("decides on the stored user when a cookie cache would serve a stale one", async () => {
      const cache = { session: { cookieCache: { enabled: true, maxAge: 60 * 60 } } };
      const byRole = await app(backend, { required: (user) => user.role === "admin", graceDays: 0 }, cache);
      const { internalAdapter } = await byRole.auth.$context;
      const ada = await byRole.signUp(EMAIL, "ada_l");
      assert.equal((await byRole.update(ada.cookie)).status, 200);
      await internalAdapter.updateUser(ada.user.id, { role: "admin" });
      assert.equal(await codeOf(await byRole.update(ada.cookie)), "TWO_FACTOR_SETUP_REQUIRED");

      // Turned on before the role made it required: it can't be turned off after.
      const grace = await byRole.signUp("grace@example.com", "grace_h");
      const cookie = await byRole.enable(grace.cookie);
      await internalAdapter.updateUser(grace.user.id, { role: "admin" });
      const disable = await post(byRole.auth, "/two-factor/disable", { password: PASSWORD }, undefined, cookie);
      assert.equal(await codeOf(disable), "TWO_FACTOR_REQUIRED");

      // Two-factor turned off behind the cached session's back.
      const all = await app(backend, { required: true, graceDays: 0 }, cache);
      const alan = await all.signUp("alan@example.com", "alan_t");
      const enabled = await all.enable(alan.cookie);
      assert.equal((await all.update(enabled)).status, 200);
      await (await all.auth.$context).internalAdapter.updateUser(alan.user.id, { twoFactorEnabled: false });
      assert.equal(await codeOf(await all.update(enabled)), "TWO_FACTOR_SETUP_REQUIRED");
    });
  });
}

describe("required two-factor options", () => {
  it("needs Better Auth's twoFactor plugin", async () => {
    const { auth } = await setup({ options: { twoFactor: { required: true } } });
    await assert.rejects(auth.$context, /twoFactor\(\) plugin/);
  });

  it("rejects an invalid graceDays", async () => {
    await assert.rejects(setup({ options: { twoFactor: { required: true, graceDays: -1 } } }), /twoFactor.graceDays/);
  });
});
