# better-auth-shield + better-auth-console: design

Status: draft for review (2026-10-23). Nothing is built yet.

Two packages, built in this order:

1. **better-auth-shield**: a Better Auth plugin for the account-security features that Better Auth leaves to the app (lockout, password policy, required 2FA, step-up), plus one security event log.
2. **better-auth-console**: an admin console that runs inside your own app and reads your own database. The shield event log is its main data source.

Target: Better Auth `>=1.6 <2` (source checked against 1.7.12). Adapters: Postgres, MySQL, SQLite, MongoDB. MIT.

## Why

| Gap | Evidence |
|---|---|
| Rate limiting is keyed on IP + path only (`createRateLimitKey(ip, path)`, `api/rate-limiter/index.ts:360`), so one attacker on many IPs, or many users behind one NAT, defeat it | #10724, #10781, #11162 |
| No password history, expiry or forced change | #2324 (+16) |
| No way to require 2FA for some users, no step-up | #5312 (+17), #10310, discussion #7093 |
| The only dashboard with security features is paid, closed source and sends auth events off-site | `@better-auth/infra`, #8754; audit logs #1184 (+34) |
| `better-auth-studio` is a dev tool (CLI that connects to the DB, like Prisma Studio), not a production console | 254★, no security features |

`better-auth-security` on npm (0.1.0, last change June 2025) is abandoned.

## How it hooks in (verified in source)

- Plugin `hooks.before` / `hooks.after` with matchers on `ctx.path`.
- After hooks run on failures too: `dispatch.ts` catches the `APIError`, sets `ctx.context.returned` to it, then runs after hooks (`dispatch.ts:407-430`). So a failed sign-in is observable without patching Better Auth.
- Plugin `schema` for our tables, `init()` for `databaseHooks`, `$ERROR_CODES` for typed errors, a client plugin for typed calls.
- With a session, `/two-factor/verify-totp` only checks the code and returns (`verify-two-factor.ts`, session branch). We reuse it for step-up.

---

## Part 1: better-auth-shield

### 1.1 Account lockout (per identifier)

Counts failed attempts per **normalized identifier**, not per IP.

- Watched endpoints: `/sign-in/email`, `/sign-in/username`, `/sign-in/phone-number`, `/sign-in/identifier`, `/sign-in/email-otp`, `/two-factor/verify-*`, plus a `paths` option for custom ones.
- Identifier taken from the body (`email`, `username`, `phoneNumber`, `identifier`), trimmed and lowercased; usernames use the `username` plugin's normalization.
- Policy (defaults): 5 failures in 15 min → locked 15 min; each further lock doubles, capped at 24 h. Success resets the counter.
- **No enumeration:** the counter runs for every identifier, existing or not, and a lock answers `429 ACCOUNT_LOCKED` with `Retry-After` for both. Never "user not found".
- **Lockout as DoS:** anyone who knows your email can lock you out. Two counters:
  - `identifier + IP`: strict (the defaults above)
  - `identifier` alone: a much higher limit (default 50 per hour) that only catches distributed attacks
  
  Both thresholds are options. A successful sign-in from a device with a valid `trust_device` / passkey can bypass the global lock (option, default on).
- Unlock: automatic on expiry, `auth.api.shieldUnlock({ identifier })` (server only), and in the console.
- Storage: `secondaryStorage` (Redis) when it has atomic `increment`, otherwise a `shieldAttempt` table updated with one atomic upsert. Counters are not read and then written separately: no race windows.

### 1.2 Per-identifier limits on codes and links

Same counter engine, separate buckets, for endpoints that **send** something:
`/email-otp/send-verification-otp`, `/phone-number/send-otp`, `/forget-password` (`/request-password-reset`), `/sign-in/magic-link`.
Default 3 sends per identifier per 10 min, 10 per day. Stops SMS-pumping and inbox flooding, which the IP limiter can't.

Upstream: send a PR adding a `key` function to `rateLimit.customRules` so this can also live in core. Shield keeps working either way.

### 1.3 Password policy

```ts
shield({
  password: {
    minLength: 12,
    history: 5,                 // last 5 hashes can't be reused
    maxAgeDays: 0,              // 0 = no expiry (NIST 800-63B advises against forced rotation)
    rejectBreached: false,      // leave to the haveIBeenPwned plugin; documented together
  },
})
```

- History check on `/change-password`, `/reset-password`, `/set-password` and the admin plugin's `set-user-password`: the plaintext is compared to stored hashes with `ctx.context.password.verify`, in a before hook, before Better Auth writes anything.
- Table `passwordHistory` (`userId`, `hash`, `createdAt`), trimmed to the last N.
- **Forced change:** `user.passwordChangeRequired` (set by admin, by `maxAgeDays`, or by our API). Sessions of such a user are limited to an allowlist (`/change-password`, `/sign-out`, `/get-session`, 2FA verify); anything else gets `403 PASSWORD_CHANGE_REQUIRED`. `getSession` exposes the flag so the app can redirect.

### 1.4 Required 2FA

```ts
shield({ twoFactor: { required: (user) => user.role === "admin", graceDays: 7 } })
```

- Needs the `twoFactor` plugin; startup fails with a clear message without it.
- Within the grace period the session works and carries `twoFactorSetupRequired: true`. After it, the session is limited to 2FA enrollment endpoints (`403 TWO_FACTOR_SETUP_REQUIRED`).
- `/two-factor/disable` is refused for users the policy covers.

### 1.5 Step-up authentication

- `POST /shield/step-up` with a TOTP, an OTP, a backup code, or the password (option). On success it stamps `session.stepUpAt`.
- Server helper `requireStepUp(headers, { maxAge: 300 })`: reads the session with `disableCookieCache`, throws `403 STEP_UP_REQUIRED`.
- Option `stepUp.paths` applies it to Better Auth's own sensitive routes (`/change-email`, `/delete-user`, `/two-factor/disable`, admin routes).
- Attempts go through the 1.1 counters.

### 1.6 Security event log

One table, `securityEvent`: `id`, `type`, `userId?`, `identifierHash`, `ip`, `userAgent`, `tenantId?`, `metadata`, `createdAt`.

- Types: `sign_in.success`, `sign_in.failure`, `lockout`, `unlock`, `code.sent_limited`, `password.changed`, `password.reuse_blocked`, `password.change_required`, `two_factor.enabled`, `two_factor.disabled`, `step_up.success`, `step_up.failure`, `session.revoked`, `sign_in.new_device`.
- Identifiers are stored as an HMAC (keyed with the auth secret), never raw, so the log doesn't become a list of emails people tried.
- `onEvent(event)` callback for webhooks, Slack, email alerts. Errors inside it are caught and logged, never fail the request.
- `retentionDays` (default 90) with a cleanup function you call from a cron (no background timers in edge runtimes).
- `tenantId` is filled when better-auth-multi-tenant is installed.

### 1.7 Testing and security bar

- Unit + integration tests on Better Auth's own test instance, run against the lowest supported, the release line and the latest Better Auth (same CI matrix as better-auth-multi-tenant).
- Required tests:
  - concurrency: 50 parallel wrong passwords must lock exactly once, with no counter lost
  - enumeration: same status, body and headers for a known and an unknown identifier
  - lockout DoS scenario
  - identifier normalization: case, whitespace, Unicode
  - each forced-state allowlist: nothing outside it works
  - cookie-cache bypass for step-up
  - every adapter: Postgres, MySQL, SQLite, Mongo
- `docs/threat-model.md` before 0.1.0: what shield stops, what it does not, and every default with its reason.
- Run our own security review on the finished code before the first release; publish with npm provenance.

---

## Part 2: better-auth-console

Admin console that **runs inside your app**: a Better Auth plugin that serves a prebuilt single-page app at `/api/auth/console` and JSON endpoints under `/console/*`. Works wherever Better Auth runs (Next.js, Hono, Express, Elysia), no separate server, no data leaves your database.

### 2.1 Access

- Only users the `admin` plugin calls admins, plus a fresh step-up (shield), plus optional IP allowlist.
- Every console action is written to the shield event log as `console.*`.
- Strict CSP, no third-party scripts or CDNs, assets bundled in the package. Requests go through Better Auth's own origin/CSRF checks.

### 2.2 v0.1 screens

| Screen | What |
|---|---|
| Overview | sign-ins per day, failures, lockouts, active sessions, 2FA adoption |
| Users | search, filter (banned, locked, no 2FA, password change required), detail |
| User detail | sessions with device/IP, revoke one/all, ban/unban, unlock, require password change, event timeline |
| Security | live event feed, filters by type/user/IP/tenant, lockouts with unlock |
| Organizations / tenants | shown only when the `organization` plugin or better-auth-multi-tenant is installed |

Later: impersonation (admin plugin), alert rules, CSV export, hosted version, longer retention.

### 2.3 Tech

Vite + React + Tailwind, built into `dist/` at publish. Icons without background tiles. Light and dark. Tested with Playwright against a sample app.

### 2.4 Positioning

"Your users, sessions and security events, in your own database, inside your own app." Not a clone of Better Auth Infra; it is the self-hosted, open option. Money later: open-core (hosted version, alerts, long retention), not by locking basic features.

---

---

## Part 3: advanced roadmap, from open Better Auth issues

Sourced from the most-reacted open issues (2026-10-23). The rule for each one: if the fix belongs in core, we send an upstream PR; if it is policy or tooling, it goes in shield/console; if it's tenant-related, it goes in better-auth-multi-tenant. Before building, check that no open PR already covers it.

### Shield

| Issue | Reactions | What we add |
|---|---|---|
| #2324 forced password change | +16 | 1.3 (already planned) |
| #5312, #10310 2FA on by default / mandatory | +17, +6 | 1.4 (already planned) |
| #8071 passkey step-up, #6000 PIN step-up | +11, +5 | 1.5 with passkey and PIN as factors |
| #1279 2FA for social-login users without a password | +26 | step-up/enrollment with a fresh OAuth re-auth or an email OTP instead of the password |
| #9690 magic links eaten by corporate email scanners | +6 | optional confirm page: GET shows a button, only POST consumes the token |
| #10724 account-based rate limiting | +5 | 1.1; plus an upstream PR for a key function |
| #6038 `get-full-organization` returns every member | +8 | hardening option: cap or strip the member list |

### Console

| Issue | Reactions | What we add |
|---|---|---|
| #3224 service accounts | +53 | non-human accounts with scoped API keys, managed from the console (big; design separately) |
| #4557, #3270 dynamic roles and permissions for the admin plugin | +27, +8 | role/permission editor in the console |
| #1595 super admin can't manage an org they aren't in | +21 | console actions run as "platform admin", audited |
| #3717, #8495 admin server APIs require a session | +14, +8 | console endpoints with their own admin auth (session plus step-up) |
| #9099 soft delete with anonymization and restore | +9 | delete → anonymize → restore window; also serves DPDP/GDPR erasure |
| #5990 multi-field user search | +6 | search across email, name, username, phone, id |
| #3056, #11096, #6940 impersonate in org, check a member's permissions, revoke by sessionId | +5 each | user/member detail actions |

### Console: support tools (our own idea, from the Q&A threads)

Most unanswered discussions are "it doesn't work" with no clue why (#5519 state_mismatch, #8368 proxy, #9606 404, #9242 cookie cache). Two tools:

- **"Why can't this user sign in?"** For one user, list every reason in one place:
  - banned
  - locked (until when, and how many failures)
  - email not verified
  - 2FA required but not set up
  - password change required
  - no credential account (social-only)
  - sessions expired or revoked
  - last failures from the event log
- **Config doctor.** Checks the running config and explains each problem:
  - `baseURL` / `trustedOrigins` don't match the request origin
  - cookie domain doesn't cover the OAuth callback host
  - `crossSubDomainCookies` is on together with multi-tenant
  - weak or default `secret`
  - proxy headers trusted without a proxy
  - cookie cache on together with step-up
  - rate limit storage is `memory` on multi-instance deploys

### better-auth-multi-tenant

| Issue | Reactions | What we add |
|---|---|---|
| #11359 tenant-scoped identity: unique (tenantId, email) | +6 | the known "users are global" limit; biggest next feature for the plugin |
| #4151 dynamic `baseURL` from the request | +37 | already done per tenant; answer the issue with how |

## Order of work

1. Shield core: counter engine + lockout (1.1) + event log (1.6), with the full test bar.
2. Code/link limits (1.2) + upstream PR for a rate-limit key function.
3. Password policy (1.3), required 2FA (1.4), step-up (1.5). Release shield 0.1.0.
4. Console v0.1 on top of the event log. Release.

## Decisions for review

1. Names: `better-auth-shield` and `better-auth-console` (both free on npm today).
2. Lockout default: strict on identifier + IP, loose on identifier alone (above). Or strict on identifier alone?
3. Locked response: `429 ACCOUNT_LOCKED` for every identifier (no enumeration). OK?
4. One repo with two packages, or two repos like the existing plugins?
5. MIT for both, paid tier only as a hosted console later?
6. Publishing needs a working npm Automation token (same blocker as better-auth-identifier).
