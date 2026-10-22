# better-auth-shield

> **Not released yet.** The code on `main` works and is tested, but no version on npm has it. 0.1.0 is next.

Account security for [Better Auth](https://better-auth.com), in one plugin:

- **Lockout per account.** Failed sign-ins are counted per email, username or phone number, not only per IP.
- **Send limits.** OTPs, magic links, reset and verification emails are capped per recipient, which stops inbox flooding and SMS pumping.
- **Password policy.** No reusing recent passwords, an optional maximum age, and forced changes.
- **Required two-factor** for everyone or the users you pick, with a grace period.
- **Step-up.** Sensitive actions ask for the password or a second factor again.
- **Security events** in your own database, with a callback for alerts.

Every feature but lockout, send limits and events is off until you set its option.

## Install

```bash
npm install better-auth-shield
```

Needs Better Auth `>=1.7.0` and Node `>=20.19`.

```ts
// auth.ts
import { betterAuth } from "better-auth";
import { shield } from "better-auth-shield";

export const auth = betterAuth({
  emailAndPassword: { enabled: true },
  plugins: [shield()],
});

// auth-client.ts
import { createAuthClient } from "better-auth/client";
import { shieldClient } from "better-auth-shield/client";

export const authClient = createAuthClient({ plugins: [shieldClient()] });
```

Run your migration afterwards (`npx @better-auth/cli migrate` or `generate`). Shield adds a `shieldCounter` and a `securityEvent` table. The password, two-factor and step-up options add the fields listed under each.

## Lockout

```ts
shield({
  lockout: {
    maxAttempts: 5,     // failures...
    window: 15 * 60,    // ...within this many seconds
    duration: 15 * 60,  // first lock; each further lock doubles it
    maxDuration: 86400, // up to this
    global: { maxAttempts: 50, window: 3600 }, // across every IP
  },
});
```

These are the defaults. There are two counters for each account:

- The **strict** one counts per account *and* IP. A stranger guessing from their own network locks only themselves out, not the real user.
- The **global** one counts per account across every IP, with a looser limit. It catches guessing spread over many addresses.

A locked request gets `429 ACCOUNT_LOCKED` with `Retry-After`. That happens before the password is checked, so a correct password doesn't get through either. Only wrong secrets count as failures (`INVALID_EMAIL_OR_PASSWORD` and its username, phone and OTP forms), not a `403` for an unverified email. A success clears the count.

Shield watches `/sign-in/email`, `/sign-in/username`, `/sign-in/phone-number`, `/sign-in/email-otp` and `/sign-in/identifier` ([better-auth-identifier](https://github.com/Weesofficial/better-auth-identifier)). Add your own with `lockout.paths: { "/sign-in/custom": "email" }`.

To unlock an account from your support tooling:

```ts
await auth.api.shieldUnlock({ body: { identifier: "ada@example.com" } });
// Also lift the step-up lock of a signed-in user:
await auth.api.shieldUnlock({ body: { identifier: "ada@example.com", userId: user.id } });
```

Better Auth's `twoFactor` plugin already locks an account after repeated wrong codes during sign-in. Shield doesn't add a second counter there; it records those failures and locks as events.

## Send limits

```ts
shield({
  sendLimit: {
    short: { max: 3, window: 600 },    // 3 per 10 minutes
    daily: { max: 10, window: 86400 }, // 10 per day
  },
});
```

These are the defaults, counted per recipient across every IP:

- covered: email OTP, phone OTP, password reset, verification email, magic link;
- also covered, by the new address: `/change-email` and `/email-otp/request-email-change`. They stay blocked while a password change or two-factor setup is due, and a request shield refuses there uses up no sends;
- also covered: `/sign-up/email` when `emailAndPassword.onExistingUserSignUp` is set and Better Auth calls it (`requireEmailVerification` on or `autoSignIn: false`). Every sign-up for the address counts, taken or not, so the limit doesn't reveal who has an account;
- the request that reaches a limit is still sent;
- later ones get `429 SEND_LIMITED` with `Retry-After`, whether or not the account exists;
- add paths with `sendLimit.paths`; set `false` (or `short: false`) to turn limits off.

## Password policy

```ts
shield({
  password: {
    history: 5,     // the new password can't be any of the last 5, counting the current one
    maxAgeDays: 0,  // 0 = never expires (NIST SP 800-63B advises against forced rotation)
    allow: [],      // extra endpoints usable while a change is required
  },
});
```

`password: {}` turns on the defaults above. Adds a `passwordHistory` table (hashes only) and `user.passwordChangeRequired`.

**Reuse.** Shield checks every endpoint that sets a password: `/change-password`, `/reset-password`, `/email-otp/reset-password`, `/phone-number/reset-password`, `/admin/set-user-password` and the server-side `setPassword`. A reused password gets `400 PASSWORD_REUSED`.

`/admin/set-user-password` is the exception: it is never refused for reuse, since the refusal would tell the admin whether a guess is one of the user's passwords, and an admin can set any password anyway. The password it replaces still goes into history, so the user's own next change can't go back to it.

The check runs only after Better Auth has accepted the reset token, the OTP or the current password. Without a valid one you can't learn whether a guess was an old password. A refused reset link stays usable, so the user can try another password.

**Forced change.** Mark a user, e.g. after a breach:

```ts
await auth.api.shieldRequirePasswordChange({ body: { userId } });
```

The same happens at sign-in when `maxAgeDays` is set and the password is older than that. Until the user changes it:

- their session stays valid;
- Better Auth endpoints other than sign-in, sign-out, session, password change and two-factor answer `403 PASSWORD_CHANGE_REQUIRED`;
- the client can read `session.user.passwordChangeRequired` to send them to the change form;
- an admin setting a new password records history but doesn't clear the flag, because a temporary password shouldn't count.

Leave length rules to Better Auth's `minPasswordLength`, and breach checks to its `haveIBeenPwned` plugin.

## Required two-factor

```ts
import { twoFactor } from "better-auth/plugins";

shield({
  twoFactor: {
    required: (user) => user.role === "admin", // or `true` for everyone
    graceDays: 7,
  },
});
// plugins: [twoFactor(), shield({ ... })]
```

Needs Better Auth's `twoFactor()` plugin; startup fails without it. Adds `user.twoFactorDueAt`.

1. The first time shield sees a covered user without two-factor (at sign-in, sign-up or any request), it sets their deadline `graceDays` from then. It records a `two_factor.setup_required` event.
2. Show `session.user.twoFactorDueAt` as a reminder. The deadline is never restarted.
3. Past it, Better Auth endpoints other than sign-in, sign-out, session, password and two-factor setup answer `403 TWO_FACTOR_SETUP_REQUIRED`.
4. `graceDays: 0` blocks from the first request.
5. A covered user can't turn two-factor off: `403 TWO_FACTOR_REQUIRED`.

Users who sign in with a social provider only need `twoFactor({ allowPasswordless: true })` to enrol.

## Step-up

```ts
import { STEP_UP_PATHS } from "better-auth-shield";

shield({
  stepUp: {
    maxAge: 300, // seconds a step-up counts as recent
    paths: [...STEP_UP_PATHS, "/organization/delete"], // defaults to STEP_UP_PATHS
  },
});
```

**Covered by default** (`STEP_UP_PATHS`):

- `/change-email`, `/email-otp/request-email-change`, `/email-otp/change-email`, `/delete-user`;
- `/link-social`, `/unlink-account`, `/passkey/generate-register-options`, `/passkey/verify-registration`;
- `/two-factor/disable`, `/two-factor/generate-backup-codes`;
- `/device/approve`, since an approved device gets a new session that would count as a fresh sign-in;
- `/electron/transfer-user`, for the same reason: its code is swapped for a new session at `/electron/token`;
- `/admin/impersonate-user`, `/admin/set-role`, `/admin/update-user`, `/admin/create-user`, `/admin/set-user-password`, `/admin/remove-user`;
- `/api-key/create`.

**How it works:**

- These endpoints answer `403 STEP_UP_REQUIRED` unless the session signed in or stepped up within `maxAge`.
- With `twoFactor({ allowPasswordless: true })`, Better Auth sets up two-factor without a password for a user who has none. For such a user, `/two-factor/enable`, `/two-factor/get-totp-uri` and a `/two-factor/verify-totp` that turns TOTP on also need a recent step-up, whatever `paths` says. A user who takes longer than `maxAge` to finish setting up signs in again.
- Adds `session.stepUpAt`.
- The user confirms with:
  - their password: `POST /shield/step-up { password }` (`authClient.shield.stepUp({ password })`);
  - or a second factor: Better Auth's own `/two-factor/verify-totp`, `verify-otp` or `verify-backup-code` while signed in.
- Wrong passwords and codes count toward a per-user lock (`429 ACCOUNT_LOCKED`) with the same rule as sign-in lockout. So do wrong passwords on `/change-password`, `/two-factor/enable` and `/two-factor/get-totp-uri`, and those endpoints are refused while the lock lasts. Better Auth caps second-factor guesses during sign-in but not on a signed-in session, so without this a stolen session could keep guessing.
- An account without a password gets `400 NO_PASSWORD` from `/shield/step-up`.

For your own routes:

```ts
// Throws 403 STEP_UP_REQUIRED unless the session confirmed within maxAge (default: stepUp.maxAge).
await auth.api.shieldRequireStepUp({ headers: request.headers, body: { maxAge: 60 } });
```

## Security events

Each event row holds:

- `type`;
- `userId`;
- `identifierHash`: an HMAC of the email or username, never the address itself;
- `ip` and `userAgent`;
- `metadata` (JSON);
- `createdAt`.

| Type | When |
| --- | --- |
| `sign_in.success`, `sign_in.failure` | Password or OTP sign-in. `metadata.twoFactorPending` when a second factor is still due |
| `lockout`, `unlock` | Lock set (`metadata.scope`: `ip`, `global`, `two_factor`, `step_up`) or lifted |
| `two_factor.success`, `two_factor.failure` | Second-factor code during sign-in |
| `two_factor.setup_required` | A required-two-factor deadline was set |
| `send.limited` | A recipient reached a send limit |
| `password.changed`, `password.reuse_blocked`, `password.change_required` | Password policy (`metadata.reason`: `max_age` or `manual`) |
| `step_up.success`, `step_up.failure` | Step-up (`metadata.method`: `password`, `totp`, `otp`, `backup_code`) |

```ts
shield({
  events: {
    retentionDays: 90,
    onEvent: async (event, { identifier }) => {
      if (event.type === "lockout") await alertSlack(`Locked: ${identifier}`);
    },
  },
});
```

`onEvent` gets the plain identifier, which the table never stores. Its errors are logged and never fail the request. `events: { enabled: false }` stops writing the table but keeps calling `onEvent`.

Shield runs no timers. Call cleanup from a cron to delete events older than `retentionDays` and idle counters:

```ts
await auth.api.shieldCleanup();
```

## Storage

Counters live in the `shieldCounter` table by default. If Better Auth has a `secondaryStorage` with an atomic `increment` (Redis), shield uses it instead. Force a choice with `storage: "database" | "secondary-storage"`. Events always go to the database.

Tests run against the memory adapter, SQLite (real SQL through Kysely) and secondary storage.

## Limits

- **Lockout can be used against a user.** Someone who knows an email can trip the global counter from many IPs and block every sign-in for that account until the lock ends. The strict, per-IP counter keeps that limit high; tune `global` or turn it off if this matters more to you than distributed guessing.
- **A send limit is a limit for everyone.** Once someone has spent a recipient's daily sends, the real user can't get a code until the window passes.
- **Counters are separate per field.** Email and username count separately, even for one account.
- **Secondary storage may log a few extra events.** Under heavy concurrency it can record slightly more failures than the limit before the lock; the lock itself holds.
- **Some refused resets spend the code.** On a non-transactional store (Better Auth's memory adapter, MongoDB without transactions), an email-OTP or phone reset refused for reuse has already used up the code. The user asks for a new one. Reset links aren't affected.
- **A cookie cache delays a newly set flag.** With `session.cookieCache` on, a `passwordChangeRequired` flag set server-side reaches an existing session within the cache's `maxAge`. Clearing a flag, a step-up and a two-factor setup are read from the database and take effect at once.
- **Required two-factor reads the user with a cookie cache on.** The cached user could miss a new role or two-factor turned off, so the gate reads the stored user on each request it covers (and always on `/two-factor/disable`): one extra user lookup per request.
- **Gates only cover Better Auth's endpoints.** For your own routes, check `session.user.passwordChangeRequired` and `twoFactorDueAt`, or call `shieldRequireStepUp`.
- **Gates cost a session lookup.** The forced-change, two-factor and step-up gates look up the session on each Better Auth request they cover (cached within a request).

The design notes and threat model are in [docs/](./docs).

## License

MIT
