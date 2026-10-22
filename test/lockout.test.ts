import assert from "node:assert/strict";
import { afterEach, describe, it, mock } from "node:test";
import { EMAIL, PASSWORD, WRONG, memoryStorage, post, setup, signIn, signUp } from "./helpers.js";

const fail = async (auth: Parameters<typeof signIn>[0], times: number, email = EMAIL, ip?: string) => {
  for (let i = 0; i < times; i++) await signIn(auth, email, WRONG, ip);
};

const backends = {
  memory: () => ({}),
  sqlite: () => ({ database: "sqlite" as const }),
  "secondary-storage": () => ({ auth: { secondaryStorage: memoryStorage() } }),
};

for (const [backend, extra] of Object.entries(backends)) {
  describe(`lockout (${backend})`, () => {
    afterEach(() => mock.timers.reset());

    it("locks after 5 failures and refuses even the right password", async () => {
      const { auth } = await setup(extra());
      await signUp(auth);
      for (let i = 0; i < 5; i++) assert.equal((await signIn(auth, EMAIL, WRONG)).status, 401);
      const res = await signIn(auth, EMAIL, PASSWORD);
      assert.equal(res.status, 429);
      assert.equal((await res.json()).code, "ACCOUNT_LOCKED");
      assert.equal(res.headers.get("retry-after"), "900");
    });

    it("answers a locked unknown email exactly like a locked real one", async () => {
      const { auth } = await setup(extra());
      await signUp(auth);
      await fail(auth, 5);
      await fail(auth, 5, "nobody@example.com");
      const known = await signIn(auth, EMAIL, WRONG);
      const unknown = await signIn(auth, "nobody@example.com", WRONG);
      assert.equal(known.status, unknown.status);
      assert.deepEqual(await known.json(), await unknown.json());
      assert.deepEqual([...known.headers.entries()], [...unknown.headers.entries()]);
    });

    it("does not lock the owner out from another IP", async () => {
      const { auth } = await setup(extra());
      await signUp(auth);
      await fail(auth, 5, EMAIL, "198.51.100.1");
      assert.equal((await signIn(auth, EMAIL, PASSWORD, "198.51.100.2")).status, 200);
    });

    it("locks across IPs on the global counter", async () => {
      const { auth } = await setup({ options: { lockout: { global: { maxAttempts: 6 } } }, ...extra() });
      await signUp(auth);
      for (let i = 0; i < 6; i++) await signIn(auth, EMAIL, WRONG, `198.51.100.${i}`);
      assert.equal((await signIn(auth, EMAIL, PASSWORD, "192.0.2.9")).status, 429);
    });

    it("resets the count after a successful sign-in", async () => {
      const { auth } = await setup(extra());
      await signUp(auth);
      await fail(auth, 4);
      assert.equal((await signIn(auth, EMAIL, PASSWORD)).status, 200);
      await fail(auth, 4);
      assert.equal((await signIn(auth, EMAIL, PASSWORD)).status, 200);
    });

    it("counts case variants as one identifier", async () => {
      const { auth } = await setup(extra());
      await signUp(auth);
      for (const email of ["ADA@example.com", "ada@EXAMPLE.com", "Ada@Example.Com", "ada@example.com", "aDA@example.COM"]) {
        await signIn(auth, email, WRONG);
      }
      assert.equal((await signIn(auth, EMAIL, PASSWORD)).status, 429);
    });

    it("unlocks after the lock time, then doubles the next lock", async () => {
      mock.timers.enable({ apis: ["Date"], now: Date.now() });
      const { auth } = await setup(extra());
      await signUp(auth);
      await fail(auth, 5);
      assert.equal((await signIn(auth, EMAIL, PASSWORD)).status, 429);
      mock.timers.tick(15 * 60 * 1000 + 1);
      await fail(auth, 5);
      const res = await signIn(auth, EMAIL, PASSWORD);
      assert.equal(res.status, 429);
      assert.equal(res.headers.get("retry-after"), "1800");
      mock.timers.tick(30 * 60 * 1000 + 1);
      assert.equal((await signIn(auth, EMAIL, PASSWORD)).status, 200);
    });

    it("forgets old failures once the window has passed", async () => {
      mock.timers.enable({ apis: ["Date"], now: Date.now() });
      const { auth } = await setup(extra());
      await signUp(auth);
      await fail(auth, 4);
      mock.timers.tick(15 * 60 * 1000 + 1);
      await fail(auth, 4);
      assert.equal((await signIn(auth, EMAIL, PASSWORD)).status, 200);
    });

    it("locks exactly once per counter under 50 parallel failures", async () => {
      const locks: unknown[] = [];
      const { auth } = await setup({
        options: { events: { onEvent: (e) => void (e.type === "lockout" && locks.push(e.metadata?.scope)) } },
        ...extra(),
      });
      await signUp(auth);
      // 50 is also the global limit, so a single lost increment would leave the global counter unlocked.
      await Promise.all(Array.from({ length: 50 }, () => signIn(auth, EMAIL, WRONG)));
      assert.deepEqual(locks.sort(), ["global", "ip"]);
      assert.equal((await signIn(auth, EMAIL, PASSWORD, "192.0.2.200")).status, 429);
    });

    it("lifts the lock with shieldUnlock", async () => {
      const { auth } = await setup(extra());
      await signUp(auth);
      await fail(auth, 5);
      await auth.api.shieldUnlock({ body: { identifier: "ADA@example.com" } });
      assert.equal((await signIn(auth, EMAIL, PASSWORD)).status, 200);
    });
  });
}

describe("lockout rules", () => {
  it("keeps shieldUnlock and shieldCleanup off the HTTP router", async () => {
    const { auth } = await setup();
    assert.equal((await post(auth, "/shield/unlock", { identifier: EMAIL })).status, 404);
    assert.equal((await post(auth, "/shield/cleanup", {})).status, 404);
  });

  it("does not count a correct password for an unverified email", async () => {
    const { auth } = await setup({ auth: { emailAndPassword: { enabled: true, requireEmailVerification: true } } });
    await signUp(auth);
    for (let i = 0; i < 6; i++) assert.equal((await signIn(auth, EMAIL, PASSWORD)).status, 403);
  });

  it("does not count requests with an invalid body", async () => {
    const { auth } = await setup();
    await signUp(auth);
    for (let i = 0; i < 6; i++) await post(auth, "/sign-in/email", { email: EMAIL });
    assert.equal((await signIn(auth, EMAIL, PASSWORD)).status, 200);
  });

  it("watches /sign-in/username", async () => {
    const { auth } = await setup();
    await signUp(auth);
    for (let i = 0; i < 5; i++) await post(auth, "/sign-in/username", { username: "ADA_L", password: WRONG });
    assert.equal((await post(auth, "/sign-in/username", { username: "ada_l", password: PASSWORD })).status, 429);
  });

  it("can be turned off", async () => {
    const { auth } = await setup({ options: { lockout: false } });
    await signUp(auth);
    await fail(auth, 10);
    assert.equal((await signIn(auth, EMAIL, PASSWORD)).status, 200);
  });

  it("rejects invalid options at startup", async () => {
    await assert.rejects(setup({ options: { lockout: { maxAttempts: 0 } } }), /lockout.maxAttempts/);
    await assert.rejects((await setup({ options: { storage: "secondary-storage" } })).auth.$context, /secondaryStorage/);
  });
});
