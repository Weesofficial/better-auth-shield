import assert from "node:assert/strict";
import { afterEach, describe, it, mock } from "node:test";
import { twoFactor, username } from "better-auth/plugins";
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
      assert.equal((await post(auth, "/two-factor/disable", { password: PASSWORD }, undefined, cookie)).status, 200);
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
