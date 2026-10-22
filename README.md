# better-auth-shield

> **In development.** This version is a name placeholder and contains no code yet. Don't install it.

Account security for [Better Auth](https://better-auth.com):

- **Account lockout** counted per email/username, not only per IP
- **Send limits** per identifier for OTPs, magic links and password-reset emails
- **Password policy**: history (no reuse), forced change
- **Required 2FA** for the users you choose, with a grace period
- **Step-up authentication** before sensitive actions
- **Security event log** kept in your own database

Design: [docs/design.md](https://github.com/Weesofficial/better-auth-shield/blob/main/docs/design.md)

MIT
