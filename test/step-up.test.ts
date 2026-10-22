import assert from "node:assert/strict";
import { afterEach, describe, it, mock } from "node:test";
import type { BetterAuthPlugin } from "better-auth";
import { createAuthEndpoint, sessionMiddleware } from "better-auth/api";
import { admin, emailOTP, twoFactor, username } from "better-auth/plugins";
import { shield, type ShieldOptions } from "../src/index.js";
import { EMAIL, PASSWORD, WRONG, cookiesOf, memoryStorage, post, setup } from "./helpers.js";

const backends = {
  memory: () => ({}),
  sqlite: () => ({ database: "sqlite" as const }),
  "secondary-storage": () => ({ auth: { secondaryStorage: memoryStorage() } }),
};

const MINUTE = 60 * 1000;

async function app(backend: keyof typeof backends, stepUp: NonNullable<ShieldOptions["stepUp"]> = { paths: ["/update-user"] }) {
  const extra = backends[backend]();
  const { auth } = await setup({
    ...extra,
    auth: {
      ...(extra as { auth?: object }).auth,
      // A cookie cache that outlives a step-up, so the stored session has to be read.
      session: { cookieCache: { enabled: true, maxAge: 60 * 60 } },
    },
    plugins: [username(), twoFactor({ skipVerificationOnEnable: true }), shield({ stepUp, sendLimit: false })],
  });
  const res = await post(auth, "/sign-up/email", { email: EMAIL, password: PASSWORD, name: "Ada", username: "ada_l" });
  const { user } = (await res.json()) as { user: { id: string } };
  const events = async () => {
    const { adapter } = await auth.$context;
    const rows = await adapter.findMany<{ type: string; metadata: string | null }>({
      model: "securityEvent",
      sortBy: { field: "createdAt", direction: "asc" },
    });
    return rows.filter((r) => r.type.startsWith("step_up.") || r.type === "lockout").map((r) => [r.type, JSON.parse(r.metadata ?? "{}")]);
  };
  const update = (cookie: string) => post(auth, "/update-user", { name: "Ada L" }, undefined, cookie);
  const stepUp_ = (cookie: string, password: string) => post(auth, "/shield/step-up", { password }, undefined, cookie);
  return { auth, user, cookie: cookiesOf(res), events, update, stepUp: stepUp_ };
}

const codeOf = async (res: Response) => ((await res.json()) as { code?: string }).code;

for (const backend of Object.keys(backends) as (keyof typeof backends)[]) {
  describe(`step-up (${backend})`, () => {
    afterEach(() => mock.timers.reset());

    it("counts a new sign-in, then asks for the password again", async () => {
      mock.timers.enable({ apis: ["Date"], now: Date.now() });
      const { cookie, events, update, stepUp } = await app(backend);
      assert.equal((await update(cookie)).status, 200);
      mock.timers.tick(6 * MINUTE);
      const blocked = await update(cookie);
      assert.equal(blocked.status, 403);
      assert.equal(await codeOf(blocked), "STEP_UP_REQUIRED");

      const wrong = await stepUp(cookie, WRONG);
      assert.equal(wrong.status, 401);
      assert.equal(await codeOf(wrong), "INVALID_PASSWORD");
      assert.equal((await stepUp(cookie, PASSWORD)).status, 200);
      // The old cookie, cache and all, still works: the stored session has the step-up.
      assert.equal((await update(cookie)).status, 200);
      mock.timers.tick(6 * MINUTE);
      assert.equal((await update(cookie)).status, 403);
      assert.deepEqual(await events(), [
        ["step_up.failure", { method: "password" }],
        ["step_up.success", { method: "password" }],
      ]);
    });

    it("locks step-up after repeated wrong passwords", async () => {
      const { cookie, events, stepUp } = await app(backend);
      for (let i = 0; i < 5; i++) assert.equal((await stepUp(cookie, WRONG)).status, 401);
      const locked = await stepUp(cookie, PASSWORD);
      assert.equal(locked.status, 429);
      assert.equal(await codeOf(locked), "ACCOUNT_LOCKED");
      assert.ok(Number(locked.headers.get("retry-after")) > 0);
      const lock = (await events()).find(([type]) => type === "lockout");
      assert.equal(lock?.[1].scope, "step_up");
    });

    it("lifts a step-up lock through shieldUnlock with the user id", async () => {
      const { auth, cookie, stepUp } = await app(backend);
      for (let i = 0; i < 5; i++) await stepUp(cookie, WRONG);
      assert.equal((await stepUp(cookie, PASSWORD)).status, 429);
      // An identifier alone doesn't touch the step-up lock.
      await auth.api.shieldUnlock({ body: { identifier: EMAIL } });
      assert.equal((await stepUp(cookie, PASSWORD)).status, 429);
      const session = await auth.api.getSession({ headers: new Headers({ cookie }) });
      await auth.api.shieldUnlock({ body: { userId: session!.user.id } });
      assert.equal((await stepUp(cookie, PASSWORD)).status, 200);
      await assert.rejects(auth.api.shieldUnlock({ body: {} }));
    });

    it("steps up with a second factor, whose guesses count toward the lock", async () => {
      mock.timers.enable({ apis: ["Date"], now: Date.now() });
      const { auth, cookie: first } = await app(backend, {});
      const enabled = await post(auth, "/two-factor/enable", { password: PASSWORD }, undefined, first);
      const { backupCodes } = (await enabled.json()) as { backupCodes: string[] };
      const cookie = cookiesOf(enabled);
      mock.timers.tick(6 * MINUTE);

      const off = await post(auth, "/two-factor/disable", { password: PASSWORD }, undefined, cookie);
      assert.equal(await codeOf(off), "STEP_UP_REQUIRED");
      const verify = (code: string) => post(auth, "/two-factor/verify-backup-code", { code }, undefined, cookie);
      assert.equal((await verify(backupCodes[0]!)).status, 200);

      // Better Auth doesn't cap codes on a signed-in session; shield does.
      for (let i = 0; i < 5; i++) assert.equal((await verify(`wrong-${i}`)).status, 401);
      assert.equal((await verify(backupCodes[1]!)).status, 429);
      // The lock covers every password check too, so a locked session can't keep guessing there.
      assert.equal((await post(auth, "/two-factor/disable", { password: PASSWORD }, undefined, cookie)).status, 429);
    });

    it("keeps the session Better Auth rotates when a first second-factor check turns it on", async () => {
      const codes: string[] = [];
      const extra = backends[backend]();
      const { auth } = await setup({
        ...extra,
        plugins: [
          username(),
          twoFactor({ otpOptions: { sendOTP: async ({ otp }) => void codes.push(otp) } }),
          shield({ stepUp: {}, sendLimit: false }),
        ],
      });
      const res = await post(auth, "/sign-up/email", { email: EMAIL, password: PASSWORD, name: "Ada", username: "ada_l" });
      const cookie = cookiesOf(res);
      assert.equal((await post(auth, "/two-factor/send-otp", {}, undefined, cookie)).status, 200);
      const verified = await post(auth, "/two-factor/verify-otp", { code: codes.at(-1) }, undefined, cookie);
      assert.equal(verified.status, 200);
      // A browser keeps the last cookie of a name; it must be the new session, not the deleted one.
      const last = verified.headers.getSetCookie().filter((c) => c.startsWith("better-auth.session_token=")).at(-1)!;
      const session = await auth.api.getSession({ headers: new Headers({ cookie: last.split(";")[0]! }) });
      assert.ok((session?.user as Record<string, unknown>).twoFactorEnabled);
      assert.ok((session?.session as Record<string, unknown>).stepUpAt);
    });

    it("counts wrong passwords on other signed-in endpoints toward the lock", async () => {
      const { auth, cookie, stepUp } = await app(backend);
      for (let i = 0; i < 5; i++) {
        const res = await post(auth, "/change-password", { currentPassword: `${WRONG}-${i}`, newPassword: "next-password-1" }, undefined, cookie);
        assert.equal(res.status, 400);
      }
      assert.equal((await post(auth, "/change-password", { currentPassword: PASSWORD, newPassword: "next-password-1" }, undefined, cookie)).status, 429);
      assert.equal((await post(auth, "/two-factor/enable", { password: PASSWORD }, undefined, cookie)).status, 429);
      assert.equal((await stepUp(cookie, PASSWORD)).status, 429);
    });

    it("guards the admin endpoints that can set a role, and the email OTP email change", async () => {
      mock.timers.enable({ apis: ["Date"], now: Date.now() });
      const extra = backends[backend]();
      const { auth } = await setup({
        ...extra,
        plugins: [username(), admin(), emailOTP({ sendVerificationOTP: async () => {}, changeEmail: { enabled: true } }), shield({ stepUp: {}, sendLimit: false })],
      });
      const res = await post(auth, "/sign-up/email", { email: EMAIL, password: PASSWORD, name: "Ada", username: "ada_l" });
      const { user } = (await res.json()) as { user: { id: string } };
      const { adapter } = await auth.$context;
      await adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { role: "admin" } });
      const cookie = cookiesOf(await post(auth, "/sign-in/email", { email: EMAIL, password: PASSWORD }));
      mock.timers.tick(6 * MINUTE);
      const calls: [string, unknown][] = [
        ["/admin/update-user", { userId: user.id, data: { role: "user" } }],
        ["/admin/create-user", { email: "eve@example.com", password: PASSWORD, name: "Eve", role: "admin" }],
        ["/email-otp/request-email-change", { newEmail: "eve@example.com" }],
        ["/email-otp/change-email", { newEmail: "eve@example.com", otp: "000000" }],
      ];
      for (const [path, body] of calls) assert.equal(await codeOf(await post(auth, path, body, undefined, cookie)), "STEP_UP_REQUIRED", path);
    });

    it("guards the Electron hand-off, which would mint a fresh session", async () => {
      mock.timers.enable({ apis: ["Date"], now: Date.now() });
      // @better-auth/electron isn't a dev dependency; a stand-in at its path, signed-in like the real one.
      const electron = {
        id: "electron-stand-in",
        endpoints: {
          transfer: createAuthEndpoint("/electron/transfer-user", { method: "POST", use: [sessionMiddleware] }, async (ctx) =>
            ctx.json({ electron_authorization_code: "code" }),
          ),
        },
      } satisfies BetterAuthPlugin;
      const extra = backends[backend]();
      const { auth } = await setup({ ...extra, plugins: [username(), electron, shield({ stepUp: {}, sendLimit: false })] });
      const res = await post(auth, "/sign-up/email", { email: EMAIL, password: PASSWORD, name: "Ada", username: "ada_l" });
      const cookie = cookiesOf(res);
      assert.equal((await post(auth, "/electron/transfer-user", {}, undefined, cookie)).status, 200);
      mock.timers.tick(6 * MINUTE);
      assert.equal(await codeOf(await post(auth, "/electron/transfer-user", {}, undefined, cookie)), "STEP_UP_REQUIRED");
    });

    it("guards two-factor setup that skips the password for a user without one", async () => {
      mock.timers.enable({ apis: ["Date"], now: Date.now() });
      const extra = backends[backend]();
      const { auth } = await setup({ ...extra, plugins: [twoFactor({ allowPasswordless: true }), shield({ stepUp: {}, sendLimit: false })] });
      const signUp = async (email: string) => {
        const res = await post(auth, "/sign-up/email", { email, password: PASSWORD, name: "Ada" });
        return { cookie: cookiesOf(res), id: ((await res.json()) as { user: { id: string } }).user.id };
      };
      const ada = await signUp(EMAIL);
      const grace = await signUp("grace@example.com");
      // Ada signs in some other way and has no password.
      const { adapter } = await auth.$context;
      await adapter.deleteMany({ model: "account", where: [{ field: "userId", value: ada.id }] });

      const enabled = await post(auth, "/two-factor/enable", {}, undefined, ada.cookie);
      assert.equal(enabled.status, 200);
      mock.timers.tick(6 * MINUTE);
      for (const [path, body] of [
        ["/two-factor/get-totp-uri", {}],
        ["/two-factor/verify-totp", { code: "000000" }],
        ["/two-factor/enable", {}],
      ] as const) {
        assert.equal(await codeOf(await post(auth, path, body, undefined, ada.cookie)), "STEP_UP_REQUIRED", path);
      }
      // A user with a password still proves it to Better Auth, so nothing changes for them.
      assert.equal((await post(auth, "/two-factor/enable", { password: PASSWORD }, undefined, grace.cookie)).status, 200);
      assert.equal((await post(auth, "/two-factor/get-totp-uri", { password: PASSWORD }, undefined, grace.cookie)).status, 200);
    });

    it("guards your own routes through shieldRequireStepUp", async () => {
      mock.timers.enable({ apis: ["Date"], now: Date.now() });
      const { auth, cookie, stepUp } = await app(backend);
      const headers = new Headers({ cookie });
      await auth.api.shieldRequireStepUp({ headers });
      mock.timers.tick(2 * MINUTE);
      await assert.rejects(auth.api.shieldRequireStepUp({ headers, body: { maxAge: 60 } }), /STEP_UP_REQUIRED|Confirm/);
      await auth.api.shieldRequireStepUp({ headers });
      mock.timers.tick(4 * MINUTE);
      await assert.rejects(auth.api.shieldRequireStepUp({ headers }), /Confirm/);
      await stepUp(cookie, PASSWORD);
      await auth.api.shieldRequireStepUp({ headers });
    });
  });
}

describe("step-up options", () => {
  it("is off by default", async () => {
    const { auth } = await setup();
    const res = await post(auth, "/sign-up/email", { email: EMAIL, password: PASSWORD, name: "Ada", username: "ada_l" });
    await assert.rejects(auth.api.shieldStepUp({ headers: new Headers({ cookie: cookiesOf(res) }), body: { password: PASSWORD } }), /stepUp/);
    const { tables } = await import("better-auth/db").then(async (m) => ({ tables: m.getAuthTables((await auth.$context).options) }));
    assert.ok(!("stepUpAt" in tables.session!.fields));
  });

  it("rejects an invalid maxAge", async () => {
    await assert.rejects(setup({ options: { stepUp: { maxAge: -5 } } }), /stepUp.maxAge/);
  });
});
