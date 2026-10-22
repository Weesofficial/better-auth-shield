import { betterAuth, type BetterAuthOptions, type BetterAuthPlugin, type SecondaryStorage } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { username } from "better-auth/plugins";
import { shield, type ShieldOptions } from "../src/index.js";

// node:sqlite arrived in Node 22; Node 20 runs only the other backends.
const sqlite = await import("node:sqlite").catch(() => null);
export const HAS_SQLITE = sqlite !== null;

export const PASSWORD = "correct-horse-battery";
export const WRONG = "wrong-password-123";
export const EMAIL = "ada@example.com";

/**
 * A real Better Auth instance with `username()` and `shield()`, over the memory
 * adapter or a migrated in-memory SQLite database (Kysely, real SQL).
 */
export async function setup({
  options = {},
  auth: authOverrides = {},
  plugins,
  database = "memory",
}: {
  options?: ShieldOptions;
  auth?: Partial<BetterAuthOptions>;
  plugins?: BetterAuthPlugin[];
  database?: "memory" | "sqlite";
} = {}) {
  const db: Record<string, Record<string, unknown>[]> = {
    user: [],
    session: [],
    account: [],
    verification: [],
    shieldCounter: [],
    securityEvent: [],
    twoFactor: [],
    passwordHistory: [],
  };
  const config = {
    secret: "test-secret-0123456789-abcdefghijklmnop",
    baseURL: "http://localhost:3000",
    database: database === "sqlite" ? new sqlite!.DatabaseSync(":memory:") : memoryAdapter(db),
    emailAndPassword: { enabled: true },
    rateLimit: { enabled: false },
    advanced: { ipAddress: { ipAddressHeaders: ["x-forwarded-for"] } },
    logger: { disabled: true },
    plugins: plugins ?? [username(), shield(options)],
    ...authOverrides,
  } satisfies BetterAuthOptions;
  if (database === "sqlite") await (await getMigrations(config)).runMigrations();
  return { auth: betterAuth(config), db };
}

type Auth = Awaited<ReturnType<typeof setup>>["auth"];

export async function signUp(auth: Auth, email = EMAIL, name = "ada_l") {
  return auth.api.signUpEmail({ body: { email, password: PASSWORD, name: "Ada", username: name } as never });
}

export function post(auth: Auth, path: string, body: unknown, ip = "203.0.113.7", cookie?: string) {
  return auth.handler(
    new Request(`http://localhost:3000/api/auth${path}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: "http://localhost:3000",
        "x-forwarded-for": ip,
        ...(cookie ? { cookie } : {}),
      },
      body: JSON.stringify(body),
    }),
  );
}

export const signIn = (auth: Auth, email: string, password: string, ip?: string) =>
  post(auth, "/sign-in/email", { email, password }, ip);

/** In-memory `SecondaryStorage` with TTLs and an atomic `increment`, like Redis. */
export function memoryStorage(): SecondaryStorage & { data: Map<string, { value: string; expires: number }> } {
  const data = new Map<string, { value: string; expires: number }>();
  const live = (key: string) => {
    const entry = data.get(key);
    if (entry && entry.expires <= Date.now()) data.delete(key);
    return data.get(key);
  };
  const expiry = (ttl?: number) => (ttl ? Date.now() + ttl * 1000 : Number.POSITIVE_INFINITY);
  return {
    data,
    get: (key) => live(key)?.value ?? null,
    getAndDelete: (key) => {
      const value = live(key)?.value ?? null;
      data.delete(key);
      return value;
    },
    set: (key, value, ttl) => {
      data.set(key, { value, expires: expiry(ttl) });
    },
    delete: (key) => {
      data.delete(key);
    },
    increment: (key, ttl) => {
      const entry = live(key);
      const next = (entry ? Number(entry.value) : 0) + 1;
      data.set(key, { value: String(next), expires: entry?.expires ?? expiry(ttl) });
      return next;
    },
  };
}

/** The `cookie` header a browser would send back after `res`. */
export const cookiesOf = (res: Response) =>
  res.headers
    .getSetCookie()
    .map((c) => c.split(";")[0])
    .join("; ");
