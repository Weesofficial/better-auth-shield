# better-auth-shield + better-auth-console: design

Status: shield built on `main` (2026-10-23), not released. Console not started.

Two packages, built in this order:

1. **better-auth-shield**: a Better Auth plugin for the account-security features that Better Auth leaves to the app (lockout, password policy, required 2FA, step-up), plus one security event log.
2. **better-auth-console**: an admin console that runs inside your own app and reads your own database. The shield event log is its main data source.

Target: Better Auth `>=1.7 <2` (source checked against 1.7.12). Adapters: Postgres, MySQL, SQLite, MongoDB. MIT.

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

## Part 1: better-auth-shield (built)

The README documents the options and defaults; [threat-model.md](./threat-model.md) covers what shield stops and what it doesn't. This part records the decisions and where they differ from the first draft.

### 1.1 Account lockout (per identifier)

- Watched: `/sign-in/email`, `/sign-in/username`, `/sign-in/phone-number`, `/sign-in/email-otp`, `/sign-in/identifier`, plus `lockout.paths`.
- Identifier from the body, trimmed and lowercased, keyed by an HMAC.
- Two counters, as drafted:
  - **strict**: identifier + IP, 5 in 15 min, lock 15 min doubling to 1 day;
  - **global**: identifier alone, 50 an hour.
- A lock is checked in a before hook, so a locked request never reaches the password check and costs no hash. Known and unknown identifiers get the same `429`.
- Only wrong-secret codes count as failures.
- **Dropped:** the trusted-device bypass. Better Auth's trust cookie only skips the second factor, so it can't vouch for a password guess.
- **Changed:** `/two-factor/verify-*` during sign-in is left to Better Auth's own lockout. Shield logs those failures and locks as events, without a second counter.
- Storage: `shieldCounter` table, one atomic `incrementOne` per write, or `secondaryStorage.increment` when present.

### 1.2 Send limits

- Covered: `/email-otp/send-verification-otp`, `/email-otp/request-password-reset`, `/forget-password/email-otp`, `/phone-number/send-otp`, `/phone-number/request-password-reset`, `/request-password-reset`, `/send-verification-email`, `/sign-in/magic-link`.
- Limits: 3 per 10 min and 10 per day, per recipient, across IPs.
- Answers `429 SEND_LIMITED` whether or not the account exists. The event is `send.limited`, not `code.sent_limited`.

### 1.3 Password policy

- **Dropped:** `minLength`, which Better Auth's `minPasswordLength` already covers. `rejectBreached` is left to `haveIBeenPwned`.
- **Changed:** the reuse check runs in a database hook (`account.update` / `account.create`), not a before hook on the endpoint:
  - Better Auth has accepted the token, OTP or current password by then, so a reset link can't be used to test old passwords;
  - the check covers every path that writes a password, including server calls.
- Forced change works as drafted. The allowlist is every Better Auth sign-in, send, password, session and two-factor endpoint (`OPEN_PATHS`), plus `password.allow`.
- An admin-set password records history but keeps the flag.

### 1.4 Required 2FA

- As drafted, with `user.twoFactorDueAt` (a date) instead of a boolean, so the app can show the deadline.
- Set once, the first time shield sees a covered user without 2FA; never restarted.
- Past it: `403 TWO_FACTOR_SETUP_REQUIRED` outside `OPEN_PATHS`. `/two-factor/disable` is refused for covered users.

### 1.5 Step-up

- **Changed:** `/shield/step-up` takes the password only. Second factors use Better Auth's own `/two-factor/verify-*` on a signed-in session, and shield stamps `session.stepUpAt` after a success. No code-checking is reimplemented.
- A new sign-in counts as a step-up: the proof time is `max(stepUpAt, session.createdAt)`.
- **Changed:** Instead of `disableCookieCache`:
  - shield re-reads the stored session when a cached one isn't recent;
  - it re-sets the cookie on success.
- `stepUp.paths` defaults to `STEP_UP_PATHS`. `shieldRequireStepUp` is the server helper for the app's own routes.
- Attempts use a per-user counter with the strict rule. Better Auth doesn't cap verify attempts on a signed-in session, so this cap is new protection, not a duplicate.

### 1.6 Security event log

- Built as drafted, minus `tenantId`. That can be added once better-auth-multi-tenant needs it.
- Not built yet:
  - `two_factor.enabled`, `two_factor.disabled`;
  - `session.revoked`;
  - `sign_in.new_device`.
- Added:
  - `two_factor.success`, `two_factor.failure`, `two_factor.setup_required`;
  - `send.limited`.
- `onEvent` receives the plain identifier; the table stores only its HMAC.

### 1.7 Testing

- Every feature runs on three backends:
  - Better Auth's memory adapter;
  - SQLite through Kysely (real SQL);
  - secondary storage.
- Time is mocked with `node:test` timers.
- Covered: concurrency (parallel failures lock once), enumeration (same answer for known and unknown), normalization, each allowlist, and a stale cookie cache after a step-up.
- Still to do before 0.1.0:
  - a CI matrix over Better Auth versions;
  - Postgres, MySQL and Mongo runs;
  - npm provenance.

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
