# Threat model

What better-auth-shield defends against, what it doesn't, and the reason behind each default. It covers the code on `main` and Better Auth 1.7.

## Assets

- **Account access:** the user's password and second factor, and the sessions they open.
- **Recipients:** the user's inbox and phone, and your SMS bill.
- **The account list:** which emails, usernames and phone numbers have accounts.
- **The event log:** it reveals who tried to sign in, from where and when.

## Attackers

| Attacker | Has | Wants |
| --- | --- | --- |
| A. Online guesser | An identifier, one or a few IPs | The password |
| B. Distributed guesser | An identifier or a leaked list, many IPs (botnet, residential proxies) | The password; credential stuffing |
| C. Flooder | An identifier or a phone number | To spam a user, or run up SMS cost (SMS pumping) |
| D. Session thief | A stolen session cookie (XSS, malware, an unlocked laptop) | To take the account over for good |
| E. Griefer | A victim's identifier | To lock the victim out |
| F. Enumerator | A list of identifiers | To learn which have accounts |
| G. Log reader | Read access to the database or a backup | Identifiers people typed |

## What shield does

### A, B: guessing

| Control | Default | Why |
| --- | --- | --- |
| Strict counter per identifier + IP | 5 failures in 15 min → lock 15 min, doubling to 1 day | Cuts an online guesser to about 20 tries a day per IP, then fewer as locks double. The window is in line with OWASP and NIST 800-63B (at most 100 failures before a lock). |
| Global counter per identifier | 50 failures an hour | Catches guessing spread across IPs, which Better Auth's IP + path limiter can't see. Kept loose so E can't easily use it (see below). |
| Lock checked before the password | — | A locked request gets `429` without a hash, so the right password doesn't help and a lock costs no CPU. |
| Only wrong secrets count | — | A `403` for an unverified email or a bad request body isn't a guess, and counting it would lock users out for typos in your client. |

**Credential stuffing** (B with a leaked list, one try per account) stays below any per-account limit by design. Shield records every failure, so an `onEvent` alert on the failure rate across accounts can catch it. Stop it with breach checks (`haveIBeenPwned`), two-factor and a bot challenge in front of sign-in.

### C: flooding and SMS pumping

| Control | Default | Why |
| --- | --- | --- |
| Per-recipient send limit | 3 per 10 min, 10 a day, across IPs | A real user rarely needs more than a couple of codes. The daily cap bounds the cost of one phone number. |
| Same answer for every recipient | `429 SEND_LIMITED` whether or not an account exists | So the limit doesn't enumerate accounts. |
| Email changes count by the new address | Same limits | A signed-in user could otherwise mail any address through `/change-email` or `/email-otp/request-email-change`. Still blocked while a password change or two-factor setup is due. |
| Sign-ups count by address with `onExistingUserSignUp` | Same limits | Better Auth mails the owner of a taken address on every attempt. Free addresses count too, so the 429 doesn't tell them apart. |

Pumping attacks rotate through many numbers, which per-recipient limits can't stop. Limit SMS by country or prefix with your provider, and keep Better Auth's IP rate limiter on.

### D: stolen session

| Control | Default | Why |
| --- | --- | --- |
| Step-up on sensitive endpoints | Off; `STEP_UP_PATHS`, 5 min when on | A thief with only a cookie can't change the email, turn off two-factor, make backup codes or delete the account without the password or a second factor. |
| A per-user cap on step-up attempts | Strict rule (5 then lock) | Better Auth doesn't cap `/two-factor/verify-*` on a signed-in session. Without the cap, a thief could keep guessing six-digit codes. |
| A new sign-in counts as a step-up | — | The user just proved themselves, and asking again is friction with no security gain. |
| Step-up on endpoints that mint a session | `/device/approve`, `/electron/transfer-user` | The new session would count as a fresh sign-in, a free step-up for the thief. |
| Step-up on passwordless two-factor setup | With `allowPasswordless`, for users without a password | Better Auth checks nothing there, so a thief could enroll their own authenticator and lock the owner out. |
| Required two-factor | Off; 7-day grace when on | A stolen password alone stops being enough for the users you choose. Covered users can't turn it off. |
| Forced password change | Off; `shieldRequirePasswordChange` or `maxAgeDays` | After a breach, a known-bad password is accepted only for the change itself. |

Step-up doesn't protect your own routes until you call `shieldRequireStepUp` from them. It also can't help when the thief has the password too: then the second factor is the defence.

### E: lockout as a weapon

Anyone who knows an email can make failures for it. Shield limits the damage:

- **The strict counter includes the IP.** The griefer locks only their own IP, and the owner can still sign in from theirs.
- **The global counter is loose.** At 50 an hour, a lock takes a deliberate distributed effort, which leaves a clear trail in the event log.
- **Support can unlock.** `shieldUnlock` lifts every lock for an identifier at once.

The trade-off is real: a global lock blocks the owner as well. If griefing worries you more than distributed guessing, raise `lockout.global` or set it to `false`.

### F: enumeration

- A lock answers the same for known and unknown identifiers: same status, body and `Retry-After`.
- Send limits answer the same for every recipient.
- The reuse check runs only after a valid reset token, OTP or current password. A stranger can't use `PASSWORD_REUSED` to test old passwords.
- `/admin/set-user-password` is never refused for reuse, so an admin can't use it to test a user's passwords. The replaced password still goes into history.

Shield doesn't change Better Auth's own answers. Sign-up and some plugin endpoints can still reveal that an account exists; see Better Auth's docs on email enumeration.

### G: the event log

- Identifiers are stored as an HMAC keyed with the auth secret, never in plain text.
- Password history stores hashes only.
- IP and user agent are stored, because an investigation needs them. Retention is 90 days by default; run `shieldCleanup` from a cron.

Someone holding both the database and the auth secret can test guesses against the HMAC. Keep the secret outside the database.

## Out of scope

- **Bots in general.** Shield counts per identifier. It doesn't challenge clients; use a CAPTCHA or bot-management service in front of sign-in.
- **Phishing.** A user who types their password and code into a fake site gives both away. Passkeys are the defence.
- **Session theft itself.** Shield limits what a stolen session can do, not how it was stolen. Cookie settings, XSS defences and short session lifetimes remain your app's job.
- **Your own endpoints.** The gates only see Better Auth's router.
- **Better Auth bugs.** Shield runs inside Better Auth and trusts its session and password checks.

## Known weaknesses

- **Secondary storage overshoot.** Under heavy concurrency, a few more failures than the limit may be logged before the lock. The lock still holds.
- **Separate counters per field.** Email and username are counted separately, so one account gets two strict budgets. That is at most 10 guesses per window instead of 5.
- **Spent reset codes.** On a store without transactions, an email-OTP or phone reset refused for reuse has already used up its code.
- **Cookie cache delay.** With `session.cookieCache`, a newly set `passwordChangeRequired` flag reaches an existing session only when the cache refreshes. Step-ups, cleared flags and required two-factor (which reads the stored user) apply at once.
- **Passwordless setup timeout.** A user without a password who takes longer than `stepUp.maxAge` to finish setting up two-factor has to sign in again.
- **A stale deadline.** A user whose two-factor deadline passed while they weren't covered is blocked immediately if they become covered again later. They don't get a new grace period.

## Reporting

Report vulnerabilities privately through GitHub's security advisories on the repository, not in public issues.
