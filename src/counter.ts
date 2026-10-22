import type { AuthContext, SecondaryStorage } from "better-auth";

export interface LockRule {
  /** Failures that trigger a lock. */
  maxAttempts: number;
  /** Seconds the failures are counted over. */
  window: number;
  /** Seconds of the first lock. Each further lock doubles it. */
  duration: number;
  /** Upper bound for a lock, in seconds. Also how long a lock is remembered for escalation. */
  maxDuration: number;
}

export interface FailResult {
  /**
   * Locked until this time (ms), or 0. Set without `justLocked` when the key
   * was already locked, so this attempt was over the limit and not counted.
   */
  lockedUntil: number;
  /** True for the one failure that created the lock. */
  justLocked: boolean;
}

export interface CounterStore {
  /** Lock end (ms) when the key is locked now, otherwise 0. */
  lockedUntil(key: string): Promise<number>;
  fail(key: string, rule: LockRule): Promise<FailResult>;
  /** Clears the failure count; a running lock and the escalation level stay. */
  reset(key: string): Promise<void>;
  /** Removes the locks and counts of one identifier (every key `<hash>` and `<hash>:<ip>`). */
  unlock(identifierHash: string): Promise<void>;
}

export const COUNTER_MODEL = "shieldCounter";

interface CounterRow {
  key: string;
  count: number;
  windowStart: number;
  lockedUntil: number;
  level: number;
}

/** Retries for compare-and-set conflicts before giving up on one failure. */
const MAX_RETRIES = 50;

const lockEnd = (now: number, rule: LockRule, level: number) =>
  now + Math.min(rule.duration * 2 ** level, rule.maxDuration) * 1000;

/**
 * Counters in the `shieldCounter` table. Every write is one `incrementOne`
 * guarded on the row it read, so concurrent failures are never lost and exactly
 * one of them creates the lock.
 */
export function databaseStore(ctx: AuthContext): CounterStore {
  const db = ctx.adapter;
  const read = async (key: string) => {
    const row = await db.findOne<CounterRow>({ model: COUNTER_MODEL, where: [{ field: "key", value: key }] });
    if (!row) return null;
    // Some adapters hand bigint columns back as strings.
    return {
      ...row,
      count: Number(row.count),
      windowStart: Number(row.windowStart),
      lockedUntil: Number(row.lockedUntil),
      level: Number(row.level),
    };
  };

  return {
    async lockedUntil(key) {
      const row = await read(key);
      return row && row.lockedUntil > Date.now() ? row.lockedUntil : 0;
    },

    async fail(key, rule) {
      for (let i = 0; i < MAX_RETRIES; i++) {
        const now = Date.now();
        const row = await read(key);
        if (!row) {
          const locks = rule.maxAttempts <= 1;
          const lockedUntil = locks ? lockEnd(now, rule, 0) : 0;
          try {
            await db.create({
              model: COUNTER_MODEL,
              data: { key, count: locks ? 0 : 1, windowStart: now, lockedUntil, level: locks ? 1 : 0 },
            });
            return { lockedUntil, justLocked: locks };
          } catch (error) {
            // Lost the race to a concurrent first failure: retry against its row.
            if (!(await read(key))) throw error;
            continue;
          }
        }
        // A request that passed the check just before the lock was created.
        if (row.lockedUntil > now) return { lockedUntil: row.lockedUntil, justLocked: false };

        const snapshot = [
          { field: "key", value: key },
          { field: "windowStart", value: row.windowStart },
          { field: "lockedUntil", value: row.lockedUntil },
        ];
        const expired = now - row.windowStart >= rule.window * 1000;
        const count = expired ? 0 : row.count;

        if (count + 1 >= rule.maxAttempts) {
          // Lock levels are forgotten once no lock has run for `maxDuration`.
          const level = now - row.lockedUntil > rule.maxDuration * 1000 ? 0 : row.level;
          const lockedUntil = lockEnd(now, rule, level);
          const won = await db.incrementOne({
            model: COUNTER_MODEL,
            where: [...snapshot, { field: "count", value: row.count }],
            increment: {},
            set: { count: 0, windowStart: now, lockedUntil, level: level + 1 },
          });
          if (won) return { lockedUntil, justLocked: true };
          continue;
        }

        const done = expired
          ? await db.incrementOne({
              model: COUNTER_MODEL,
              where: [...snapshot, { field: "count", value: row.count }],
              increment: {},
              set: { count: 1, windowStart: now },
            })
          : await db.incrementOne({
              model: COUNTER_MODEL,
              // Never past the attempt before the lock: that one has to go through the branch above.
              where: [...snapshot, { field: "count", operator: "lt", value: rule.maxAttempts - 1 }],
              increment: { count: 1 },
              set: {},
            });
        if (done) return { lockedUntil: 0, justLocked: false };
      }
      throw new Error("better-auth-shield: too much contention on one counter");
    },

    async reset(key) {
      await db.updateMany({ model: COUNTER_MODEL, where: [{ field: "key", value: key }], update: { count: 0 } });
    },

    async unlock(hash) {
      await db.deleteMany({ model: COUNTER_MODEL, where: [{ field: "key", value: hash }] });
      await db.deleteMany({ model: COUNTER_MODEL, where: [{ field: "key", operator: "starts_with", value: `${hash}:` }] });
    },
  };
}

/**
 * Counters in `secondaryStorage` (Redis and the like). Relies on its atomic
 * `increment`: exactly one failure sees the count reach the limit.
 *
 * `maxLockSeconds` is the longest lock any rule can set; unlock markers live
 * that long.
 */
export function secondaryStore(storage: SecondaryStorage, maxLockSeconds: number): CounterStore {
  const n = (key: string) => `shield:n:${key}`;
  const lock = (key: string) => `shield:lock:${key}`;
  const level = (key: string) => `shield:level:${key}`;
  // A secondary storage can't delete by prefix, so an unlock is a marker that
  // voids every lock of that identifier created before it.
  const unlocked = (key: string) => `shield:unlocked:${key.split(":")[0]}`;

  const lockedUntil = async (key: string) => {
    const value = await storage.get(lock(key));
    const data = (typeof value === "string" ? JSON.parse(value) : value) as { at: number; until: number } | null;
    if (!data || data.until <= Date.now()) return 0;
    const unlockedAt = Number(await storage.get(unlocked(key))) || 0;
    return data.at <= unlockedAt ? 0 : data.until;
  };

  return {
    lockedUntil,

    async fail(key, rule) {
      const current = await lockedUntil(key);
      if (current) return { lockedUntil: current, justLocked: false };
      const count = await storage.increment(n(key), rule.window);
      if (count < rule.maxAttempts) return { lockedUntil: 0, justLocked: false };
      // Raced past the check while another request was creating the lock.
      if (count > rule.maxAttempts) {
        return { lockedUntil: (await lockedUntil(key)) || Date.now() + rule.duration * 1000, justLocked: false };
      }
      const now = Date.now();
      const lvl = (await storage.increment(level(key), rule.maxDuration)) - 1;
      const until = lockEnd(now, rule, lvl);
      await storage.set(lock(key), JSON.stringify({ at: now, until }), Math.ceil((until - now) / 1000));
      await storage.delete(n(key));
      return { lockedUntil: until, justLocked: true };
    },

    async reset(key) {
      await storage.delete(n(key));
    },

    async unlock(hash) {
      await storage.set(unlocked(hash), String(Date.now()), maxLockSeconds);
      await storage.delete(n(hash));
      await storage.delete(level(hash));
    },
  };
}
