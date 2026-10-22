import assert from "node:assert/strict";
import { afterEach, describe, it, mock } from "node:test";
import { admin, emailOTP, username } from "better-auth/plugins";
import { shield, type ShieldOptions } from "../src/index.js";
import { EMAIL, PASSWORD, cookiesOf, memoryStorage, post, setup, signIn } from "./helpers.js";

const backends = {
  memory: () => ({}),
  sqlite: () => ({ database: "sqlite" as const }),
  "secondary-storage": () => ({ auth: { secondaryStorage: memoryStorage() } }),
};

const SECOND = "second-password-456";
const THIRD = "third-password-789";

async function app(backend: keyof typeof backends, password: ShieldOptions["password"] = {}) {
  const otps: string[] = [];
  const tokens: string[] = [];
  const extra = backends[backend]();
  const { auth, db } = await setup({
    ...extra,
    auth: {
      ...(extra as { auth?: object }).auth,
      emailAndPassword: { enabled: true, sendResetPassword: async ({ token }) => void tokens.push(token) },
    },
    plugins: [
      username(),
      admin(),
      emailOTP({ sendVerificationOTP: async ({ otp }) => void otps.push(otp) }),
      shield({ password, sendLimit: false }),
    ],
  });
  const res = await post(auth, "/sign-up/email", { email: EMAIL, password: PASSWORD, name: "Ada", username: "ada_l" });
  const { user } = await res.json();
  const events = async () => {
    const { adapter } = await auth.$context;
    const rows = await adapter.findMany<{ type: string; createdAt: Date }>({
      model: "securityEvent",
      sortBy: { field: "createdAt", direction: "asc" },
    });
    return rows.map((r) => r.type).filter((t) => t.startsWith("password."));
  };
  return { auth, db, user: user as { id: string }, cookie: cookiesOf(res), otps, tokens, events };
}

const change = (auth: Parameters<typeof post>[0], cookie: string, currentPassword: string, newPassword: string) =>
  post(auth, "/change-password", { currentPassword, newPassword }, undefined, cookie);

const codeOf = async (res: Response) => (await res.json()).code;

for (const backend of Object.keys(backends) as (keyof typeof backends)[]) {
  describe(`password policy (${backend})`, () => {
    afterEach(() => mock.timers.reset());

    it("blocks the current and recent passwords on change-password", async () => {
      const { auth, cookie, events } = await app(backend);
      const same = await change(auth, cookie, PASSWORD, PASSWORD);
      assert.equal(same.status, 400);
      assert.equal(await codeOf(same), "PASSWORD_REUSED");
      assert.equal((await change(auth, cookie, PASSWORD, SECOND)).status, 200);
      assert.equal(await codeOf(await change(auth, cookie, SECOND, PASSWORD)), "PASSWORD_REUSED");
      assert.equal((await change(auth, cookie, SECOND, THIRD)).status, 200);
      assert.equal((await signIn(auth, EMAIL, THIRD)).status, 200);
      assert.deepEqual(await events(), [
        "password.reuse_blocked",
        "password.changed",
        "password.reuse_blocked",
        "password.changed",
      ]);
    });

    it("keeps only `history - 1` old hashes", async () => {
      const { auth, cookie } = await app(backend, { history: 2 });
      await change(auth, cookie, PASSWORD, SECOND);
      await change(auth, cookie, SECOND, THIRD);
      const { adapter } = await auth.$context;
      assert.equal(await adapter.count({ model: "passwordHistory" }), 1);
      // The first password has dropped out of a two-password history.
      assert.equal((await change(auth, cookie, THIRD, PASSWORD)).status, 200);
    });

    it("allows reuse with history: 0", async () => {
      const { auth, cookie } = await app(backend, { history: 0 });
      assert.equal((await change(auth, cookie, PASSWORD, PASSWORD)).status, 200);
    });

    it("checks reset links, and a refused password leaves the link usable", async () => {
      const { auth, tokens, events } = await app(backend);
      await post(auth, "/request-password-reset", { email: EMAIL });
      const token = tokens.at(-1)!;
      const reused = await post(auth, "/reset-password", { token, newPassword: PASSWORD });
      assert.equal(await codeOf(reused), "PASSWORD_REUSED");
      assert.equal((await post(auth, "/reset-password", { token, newPassword: SECOND })).status, 200);
      assert.equal((await signIn(auth, EMAIL, SECOND)).status, 200);
      assert.deepEqual(await events(), ["password.reuse_blocked", "password.changed"]);
    });

    it("checks a reset token sent in the query behind an empty body token", async () => {
      const { auth, tokens } = await app(backend);
      await post(auth, "/request-password-reset", { email: EMAIL });
      const reused = await post(auth, `/reset-password?token=${tokens.at(-1)!}`, { token: "", newPassword: PASSWORD });
      assert.equal(await codeOf(reused), "PASSWORD_REUSED");
    });

    it("never says PASSWORD_REUSED to someone without a valid code or token", async () => {
      const { auth, events } = await app(backend);
      await post(auth, "/email-otp/request-password-reset", { email: EMAIL });
      const wrongOtp = await post(auth, "/email-otp/reset-password", { email: EMAIL, otp: "000000", password: PASSWORD });
      assert.notEqual(await codeOf(wrongOtp), "PASSWORD_REUSED");
      const wrongToken = await post(auth, "/reset-password", { token: "not-a-token", newPassword: PASSWORD });
      assert.notEqual(await codeOf(wrongToken), "PASSWORD_REUSED");
      const noSession = await post(auth, "/change-password", { currentPassword: PASSWORD, newPassword: PASSWORD });
      assert.notEqual(await codeOf(noSession), "PASSWORD_REUSED");
      assert.deepEqual(await events(), []);
    });

    it("checks email OTP resets once the code is right", async () => {
      const { auth, otps } = await app(backend);
      await post(auth, "/email-otp/request-password-reset", { email: EMAIL });
      const otp = otps.at(-1)!;
      const reused = await post(auth, "/email-otp/reset-password", { email: EMAIL, otp, password: PASSWORD });
      assert.equal(await codeOf(reused), "PASSWORD_REUSED");
      await post(auth, "/email-otp/request-password-reset", { email: EMAIL });
      const ok = await post(auth, "/email-otp/reset-password", { email: EMAIL, otp: otps.at(-1)!, password: SECOND });
      assert.equal(ok.status, 200);
    });

    it("forces a change: other endpoints get 403 until the user picks a new password", async () => {
      const { auth, user, cookie, events } = await app(backend);
      await auth.api.shieldRequirePasswordChange({ body: { userId: user.id } });
      const blocked = await post(auth, "/update-user", { name: "Ada L" }, undefined, cookie);
      assert.equal(blocked.status, 403);
      assert.equal(await codeOf(blocked), "PASSWORD_CHANGE_REQUIRED");
      const session = await auth.api.getSession({ headers: new Headers({ cookie }) });
      assert.equal((session?.user as Record<string, unknown>).passwordChangeRequired, true);
      assert.equal((await change(auth, cookie, PASSWORD, SECOND)).status, 200);
      assert.equal((await post(auth, "/update-user", { name: "Ada L" }, undefined, cookie)).status, 200);
      assert.deepEqual(await events(), ["password.change_required", "password.changed"]);
    });

    it("an admin-set password records history but doesn't satisfy a forced change", async () => {
      const { auth, user, cookie } = await app(backend);
      const { adapter } = await auth.$context;
      await post(auth, "/sign-up/email", { email: "root@example.com", password: PASSWORD, name: "Root", username: "root" });
      await adapter.update({ model: "user", where: [{ field: "email", value: "root@example.com" }], update: { role: "admin" } });
      const root = cookiesOf(await signIn(auth, "root@example.com", PASSWORD));
      await auth.api.shieldRequirePasswordChange({ body: { userId: user.id } });
      const set = await post(auth, "/admin/set-user-password", { userId: user.id, newPassword: SECOND }, undefined, root);
      assert.equal(set.status, 200);
      assert.equal((await post(auth, "/update-user", { name: "Ada L" }, undefined, cookie)).status, 403);
      assert.equal(await codeOf(await change(auth, cookie, SECOND, PASSWORD)), "PASSWORD_REUSED");
      assert.equal((await change(auth, cookie, SECOND, THIRD)).status, 200);
    });

    it("never tells an admin whether a password is one of the user's", async () => {
      const { auth, user, cookie } = await app(backend);
      const { adapter } = await auth.$context;
      await post(auth, "/sign-up/email", { email: "root@example.com", password: PASSWORD, name: "Root", username: "root" });
      await adapter.update({ model: "user", where: [{ field: "email", value: "root@example.com" }], update: { role: "admin" } });
      const root = cookiesOf(await signIn(auth, "root@example.com", PASSWORD));
      const set = (newPassword: string) => post(auth, "/admin/set-user-password", { userId: user.id, newPassword }, undefined, root);
      // The user's current password, then a new one: both just succeed.
      assert.equal((await set(PASSWORD)).status, 200);
      assert.equal((await set(SECOND)).status, 200);
      // The passwords replaced are still history for the user's own change.
      assert.equal(await codeOf(await change(auth, cookie, SECOND, PASSWORD)), "PASSWORD_REUSED");
      assert.equal((await change(auth, cookie, SECOND, THIRD)).status, 200);
    });

    it("flags a password older than maxAgeDays at sign-in", async () => {
      mock.timers.enable({ apis: ["Date"], now: Date.now() });
      const { auth } = await app(backend, { maxAgeDays: 90 });
      const fresh = await signIn(auth, EMAIL, PASSWORD);
      assert.equal((await post(auth, "/update-user", { name: "A" }, undefined, cookiesOf(fresh))).status, 200);
      mock.timers.tick(91 * 24 * 60 * 60 * 1000);
      const old = await signIn(auth, EMAIL, PASSWORD);
      assert.equal(old.status, 200);
      const cookie = cookiesOf(old);
      assert.equal(await codeOf(await post(auth, "/update-user", { name: "B" }, undefined, cookie)), "PASSWORD_CHANGE_REQUIRED");
      assert.equal((await change(auth, cookie, PASSWORD, SECOND)).status, 200);
      assert.equal((await post(auth, "/update-user", { name: "C" }, undefined, cookie)).status, 200);
      const again = await signIn(auth, EMAIL, SECOND);
      assert.equal((await post(auth, "/update-user", { name: "D" }, undefined, cookiesOf(again))).status, 200);
    });
  });
}

describe("password policy options", () => {
  it("is off by default", async () => {
    const { auth } = await setup();
    const { tables } = await import("better-auth/db").then(async (m) => ({ tables: m.getAuthTables((await auth.$context).options) }));
    assert.ok(!("passwordHistory" in tables));
    await assert.rejects(auth.api.shieldRequirePasswordChange({ body: { userId: "x" } }), /password/);
  });

  it("rejects invalid options at startup", async () => {
    await assert.rejects(setup({ options: { password: { history: -1 } } }), /password.history/);
    await assert.rejects(setup({ options: { password: { maxAgeDays: 1.5 } } }), /password.maxAgeDays/);
  });
});
