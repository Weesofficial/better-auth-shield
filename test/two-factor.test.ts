import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { twoFactor } from "better-auth/plugins";
import { shield } from "../src/index.js";
import { EMAIL, PASSWORD, cookiesOf, post, setup, signIn, signUp } from "./helpers.js";

async function withTwoFactor(database: "memory" | "sqlite") {
  const events: { type: string; userId: string | null; metadata: Record<string, unknown> | null }[] = [];
  const { auth } = await setup({
    database,
    plugins: [twoFactor({ skipVerificationOnEnable: true }), shield({ events: { onEvent: (e) => void events.push(e) } })],
  });
  const { user } = await signUp(auth);
  const session = cookiesOf(await signIn(auth, EMAIL, PASSWORD));
  const res = await post(auth, "/two-factor/enable", { password: PASSWORD }, undefined, session);
  const { backupCodes } = (await res.json()) as { backupCodes: string[] };
  events.length = 0;
  return { auth, user, backupCodes, events };
}

for (const database of ["memory", "sqlite"] as const) {
  describe(`second factor (${database})`, () => {
    it("records a pending password sign-in, failed codes with the user, then the success", async () => {
      const { auth, user, backupCodes, events } = await withTwoFactor(database);
      const pending = await signIn(auth, EMAIL, PASSWORD);
      assert.equal(((await pending.json()) as { twoFactorRedirect?: boolean }).twoFactorRedirect, true);
      const cookie = cookiesOf(pending);

      const wrong = await post(auth, "/two-factor/verify-backup-code", { code: "not-a-code" }, undefined, cookie);
      assert.equal(wrong.status, 401);
      const ok = await post(auth, "/two-factor/verify-backup-code", { code: backupCodes[0] }, undefined, cookie);
      assert.equal(ok.status, 200);

      assert.deepEqual(
        events.map((e) => [e.type, e.userId, e.metadata?.code ?? e.metadata?.twoFactorPending ?? null]),
        [
          ["sign_in.success", null, true],
          ["two_factor.failure", user.id, "INVALID_BACKUP_CODE"],
          ["two_factor.success", user.id, null],
        ],
      );
    });

    it("records Better Auth's own second-factor lockout once, and no refusals", async () => {
      const { auth, user, events } = await withTwoFactor(database);
      // Better Auth allows 5 codes per challenge and locks the account after 10 failures.
      for (let challenge = 0; challenge < 3; challenge++) {
        const cookie = cookiesOf(await signIn(auth, EMAIL, PASSWORD));
        for (let i = 0; i < 6; i++) await post(auth, "/two-factor/verify-backup-code", { code: `wrong-${i}` }, undefined, cookie);
      }
      const ours = events.filter((e) => e.type !== "sign_in.success");
      assert.equal(ours.filter((e) => e.type === "two_factor.failure").length, 10);
      const locks = ours.filter((e) => e.type === "lockout");
      assert.equal(locks.length, 1);
      assert.equal(locks[0]!.userId, user.id);
      assert.equal(locks[0]!.metadata?.scope, "two_factor");
      assert.equal(ours.at(-1), locks[0]);
    });

    it("ignores a request without a two-factor cookie", async () => {
      const { auth, events } = await withTwoFactor(database);
      assert.equal((await post(auth, "/two-factor/verify-backup-code", { code: "x" })).status, 401);
      assert.deepEqual(events, []);
    });
  });
}
