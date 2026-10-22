import assert from "node:assert/strict";
import { afterEach, describe, it, mock } from "node:test";
import { emailOTP, magicLink } from "better-auth/plugins";
import { shield, type ShieldOptions } from "../src/index.js";
import { EMAIL, PASSWORD, cookiesOf, memoryStorage, post, setup, signUp } from "./helpers.js";

const backends = {
  memory: () => ({}),
  sqlite: () => ({ database: "sqlite" as const }),
  "secondary-storage": () => ({ auth: { secondaryStorage: memoryStorage() } }),
};

for (const [backend, extra] of Object.entries(backends)) {
  describe(`send limits (${backend})`, () => {
    afterEach(() => mock.timers.reset());

    async function app(options: ShieldOptions = {}) {
      const sent: string[] = [];
      const events: { type: string; metadata: Record<string, unknown> | null }[] = [];
      const base: { auth?: object; database?: "sqlite" } = extra();
      const { auth } = await setup({
        ...base,
        auth: {
          ...base.auth,
          emailAndPassword: { enabled: true, sendResetPassword: async ({ user }) => void sent.push(`reset:${user.email}`) },
        },
        plugins: [
          magicLink({ sendMagicLink: async ({ email }) => void sent.push(`link:${email}`) }),
          shield({ ...options, events: { onEvent: (e) => void events.push(e) } }),
        ],
      });
      const link = (email: string, ip?: string) => post(auth, "/sign-in/magic-link", { email }, ip);
      return { auth, sent, events, link };
    }

    it("sends 3 codes per 10 minutes, then answers 429 with Retry-After", async () => {
      const { sent, link } = await app();
      for (let i = 0; i < 3; i++) assert.equal((await link(EMAIL, `198.51.100.${i}`)).status, 200);
      const res = await link(EMAIL, "192.0.2.1");
      assert.equal(res.status, 429);
      assert.equal(((await res.json()) as { code: string }).code, "SEND_LIMITED");
      assert.equal(res.headers.get("retry-after"), "600");
      assert.equal(sent.length, 3);
    });

    it("answers a limited unknown address exactly like a real account", async () => {
      const { auth, sent } = await app();
      await signUp(auth);
      const reset = (email: string) => post(auth, "/request-password-reset", { email });
      for (let i = 0; i < 3; i++) {
        await reset(EMAIL);
        await reset("nobody@example.com");
      }
      const known = await reset(EMAIL);
      const unknown = await reset("nobody@example.com");
      assert.equal(known.status, 429);
      assert.equal(known.status, unknown.status);
      assert.deepEqual(await known.json(), await unknown.json());
      assert.deepEqual([...known.headers.entries()], [...unknown.headers.entries()]);
      assert.deepEqual(sent, ["reset:ada@example.com", "reset:ada@example.com", "reset:ada@example.com"]);
    });

    it("counts case variants as one address and leaves other addresses alone", async () => {
      const { link } = await app();
      for (const email of ["ADA@example.com", "ada@EXAMPLE.com", "Ada@Example.com"]) await link(email);
      assert.equal((await link(EMAIL)).status, 429);
      assert.equal((await link("grace@example.com")).status, 200);
    });

    it("opens again after the window, and stops for the day after 10", async () => {
      mock.timers.enable({ apis: ["Date"], now: Date.now() });
      const { sent, events, link } = await app();
      for (let round = 0; round < 4; round++) {
        for (let i = 0; i < 3; i++) await link(EMAIL);
        mock.timers.tick(10 * 60 * 1000 + 1);
      }
      assert.equal(sent.length, 10, "the fourth round stops at the daily limit");
      const res = await link(EMAIL);
      assert.equal(res.status, 429);
      assert.ok(Number(res.headers.get("retry-after")) > 20 * 60 * 60);
      assert.deepEqual(
        events.filter((e) => e.type === "send.limited").map((e) => e.metadata?.scope),
        ["short", "short", "short", "daily"],
      );
    });

    it("sends exactly 3 under 20 parallel requests", async () => {
      const { sent, events, link } = await app();
      const statuses = await Promise.all(Array.from({ length: 20 }, (_, i) => link(EMAIL, `198.51.100.${i}`).then((r) => r.status)));
      assert.equal(sent.length, 3);
      assert.equal(statuses.filter((s) => s === 200).length, 3);
      assert.equal(events.filter((e) => e.type === "send.limited").length, 1);
    });

    it("is lifted by shieldUnlock", async () => {
      const { auth, link } = await app();
      for (let i = 0; i < 3; i++) await link(EMAIL);
      await auth.api.shieldUnlock({ body: { identifier: EMAIL } });
      assert.equal((await link(EMAIL)).status, 200);
    });

    it("can be turned off, or tuned per window", async () => {
      const off = await app({ sendLimit: false });
      for (let i = 0; i < 5; i++) assert.equal((await off.link(EMAIL)).status, 200);
      const tuned = await app({ sendLimit: { short: { max: 5 }, daily: false } });
      for (let i = 0; i < 5; i++) assert.equal((await tuned.link(EMAIL)).status, 200);
      assert.equal((await tuned.link(EMAIL)).status, 429);
    });

    it("limits email changes by the new address, and keeps them shut during a forced password change", async () => {
      const sent: string[] = [];
      const base: { auth?: object; database?: "sqlite" } = extra();
      const { auth } = await setup({
        ...base,
        auth: {
          ...base.auth,
          user: { changeEmail: { enabled: true } },
          emailVerification: { sendVerificationEmail: async ({ user }) => void sent.push(`verify:${user.email}`) },
        },
        plugins: [
          magicLink({ sendMagicLink: async ({ email }) => void sent.push(`link:${email}`) }),
          emailOTP({ sendVerificationOTP: async ({ email }) => void sent.push(`otp:${email}`), changeEmail: { enabled: true } }),
          shield({ password: {} }),
        ],
      });
      const cookie = cookiesOf(await post(auth, "/sign-up/email", { email: EMAIL, password: PASSWORD, name: "Ada" }));
      const change = (newEmail: string) => post(auth, "/change-email", { newEmail }, undefined, cookie);
      const otp = (newEmail: string) => post(auth, "/email-otp/request-email-change", { newEmail }, undefined, cookie);

      for (let i = 0; i < 3; i++) assert.equal((await change("victim@example.com")).status, 200);
      const limited = await change("Victim@Example.com");
      assert.equal(limited.status, 429);
      assert.equal(((await limited.json()) as { code: string }).code, "SEND_LIMITED");
      // One count per address, whichever endpoint sends.
      assert.equal((await otp("victim@example.com")).status, 429);
      assert.equal((await post(auth, "/sign-in/magic-link", { email: "victim@example.com" })).status, 429);
      assert.deepEqual(sent, ["verify:victim@example.com", "verify:victim@example.com", "verify:victim@example.com"]);

      const { user } = (await auth.api.getSession({ headers: new Headers({ cookie }) }))!;
      await auth.api.shieldRequirePasswordChange({ body: { userId: user.id } });
      for (let i = 0; i < 4; i++) {
        const blocked = await otp("grace@example.com");
        assert.equal(blocked.status, 403);
        assert.equal(((await blocked.json()) as { code: string }).code, "PASSWORD_CHANGE_REQUIRED");
      }
      await post(auth, "/change-password", { currentPassword: PASSWORD, newPassword: "next-password-1" }, undefined, cookie);
      // The refused requests used up none of the address's sends.
      for (let i = 0; i < 3; i++) assert.equal((await otp("grace@example.com")).status, 200);
      assert.equal((await otp("grace@example.com")).status, 429);
    });
  });
}

describe("send limit options", () => {
  it("rejects invalid limits at startup", async () => {
    await assert.rejects(setup({ options: { sendLimit: { short: { max: 0 } } } }), /sendLimit.short.maxAttempts/);
  });
});
