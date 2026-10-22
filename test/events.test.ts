import assert from "node:assert/strict";
import { describe, it, mock } from "node:test";
import { hashIdentifier, normalizeIdentifier } from "../src/index.js";
import { EMAIL, PASSWORD, WRONG, setup, signIn, signUp } from "./helpers.js";

describe("security events", () => {
  it("records failures, the lockout and a success, without storing the email", async () => {
    const { auth, db } = setup({ options: { lockout: { maxAttempts: 2 } } });
    const { user } = await signUp(auth);
    await signIn(auth, EMAIL, WRONG);
    await signIn(auth, EMAIL, WRONG);
    await auth.api.shieldUnlock({ body: { identifier: EMAIL } });
    await signIn(auth, EMAIL, PASSWORD);

    const types = db.securityEvent!.map((e) => e.type);
    assert.deepEqual(types, ["sign_in.failure", "sign_in.failure", "lockout", "unlock", "sign_in.success"]);
    const hash = await hashIdentifier("test-secret-0123456789-abcdefghijklmnop", EMAIL);
    assert.ok(db.securityEvent!.every((e) => e.identifierHash === hash));
    assert.equal(db.securityEvent!.at(-1)!.userId, user.id);
    assert.equal(db.securityEvent![0]!.ip, "203.0.113.7");
    assert.equal(JSON.parse(String(db.securityEvent![2]!.metadata)).scope, "ip");
    const shieldRows = JSON.stringify([db.securityEvent, db.shieldCounter]);
    assert.ok(!shieldRows.includes("ada@") && !shieldRows.includes("example.com"), "raw email stored by shield");
  });

  it("passes the identifier to onEvent and survives a throwing callback", async () => {
    const seen: (string | null)[] = [];
    const { auth } = setup({
      options: {
        events: {
          onEvent: (_event, { identifier }) => {
            seen.push(identifier);
            throw new Error("webhook down");
          },
        },
      },
    });
    await signUp(auth);
    assert.equal((await signIn(auth, "Ada@Example.com", WRONG)).status, 401);
    assert.equal((await signIn(auth, EMAIL, PASSWORD)).status, 200);
    assert.deepEqual(seen, [EMAIL, EMAIL]);
  });

  it("writes nothing when events are disabled", async () => {
    const { auth, db } = setup({ options: { events: { enabled: false } } });
    await signUp(auth);
    await signIn(auth, EMAIL, WRONG);
    assert.equal(db.securityEvent!.length, 0);
  });

  it("cleanup removes old events and idle counters only", async () => {
    mock.timers.enable({ apis: ["Date"], now: Date.now() });
    try {
      const { auth, db } = setup();
      await signUp(auth);
      await signIn(auth, EMAIL, WRONG);
      mock.timers.tick(91 * 24 * 60 * 60 * 1000);
      await signIn(auth, "grace@example.com", WRONG);
      const result = await auth.api.shieldCleanup();
      // Each identifier has two counters: per IP and global.
      assert.deepEqual(result, { events: 1, counters: 2 });
      assert.equal(db.securityEvent!.length, 1);
      assert.equal(db.shieldCounter!.length, 2);
    } finally {
      mock.timers.reset();
    }
  });
});

describe("normalizeIdentifier", () => {
  it("folds case, whitespace and Unicode compatibility forms", () => {
    assert.equal(normalizeIdentifier("email", "  ＡＤＡ@Example.COM "), EMAIL);
    assert.equal(normalizeIdentifier("phoneNumber", "+91 (98) 765-432.10"), "+919876543210");
    assert.equal(normalizeIdentifier("email", "   "), null);
    assert.equal(normalizeIdentifier("email", 42), null);
    assert.equal(normalizeIdentifier("email", "a".repeat(10_000))!.length, 320);
  });
});
