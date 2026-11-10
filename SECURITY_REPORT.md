# Security & Bug Review of `AITRC.html`

The original is a single HTML file with all logic and data in the browser (`localStorage`).
That design cannot be made secure, because every "check" runs on the attacker's own machine.
I confirmed the items marked **[verified]** by running the original in a headless browser.

## Security issues

| # | Severity | Issue in original | Fix in this version |
|---|----------|-------------------|---------------------|
| 1 | Critical | **No real authentication.** Role is read from `localStorage`; typing 3 keys in the console opens the HOD dashboard with no password **[verified]** | Server-side sessions; every API call re-checks the role against the database |
| 2 | Critical | **Stored XSS.** Subject/name/description inserted with `innerHTML`; a student's `<img onerror=...>` ran in the HOD's browser **[verified]** | UI built with `textContent` only; strict CSP; no inline scripts/handlers; tests assert this |
| 3 | Critical | **Default passwords** `student123` / `hod123` printed on the login page. Any PRN auto-registers with the default, so anyone can log in as anyone **[verified]** | HOD sets own password via one-time registration protected by a setup code, hashed (PBKDF2-SHA256); students register their own password; defaults removed |
| 4 | High | Passwords stored in plaintext in `localStorage` | Salted hashes in SQLite; password change invalidates other sessions |
| 5 | High | Data visible/editable by any user of the browser; complaints never reach another device (HOD can't actually see students' complaints) | Central database; HOD can only read/update complaints of their own level + department (others return 404) |
| 6 | High | **"100% anonymous" was false** - PRN stored with every complaint **[verified]** | Blank name = PRN not stored at all |
| 7 | High | 6-digit PIN from `Math.random()`, no rate limit, PIN visible to HOD | 60-bit random code from `secrets`, stored only as a SHA-256 hash, shown once, tracking attempts rate-limited |
| 8 | Medium | No brute-force protection | Lockout after 5 failed logins / 15 min, plus per-IP limits on register, submit, track |
| 9 | Medium | CSV export vulnerable to **formula injection** (`=HYPERLINK(...)`) | Cells starting with `= + - @` are neutralised |
| 10 | Medium | No CSRF/clickjacking/MIME protections (none needed offline, required with a server) | CSRF token on every write, `SameSite=Lax`, `HttpOnly` cookie, `X-Frame-Options`, `nosniff`, CSP, `no-store` on API |
| 11 | Medium | No input limits (huge text fills storage) | Server-side length/type validation, 32 KB body cap, control characters stripped |
| 12 | Low | No audit trail | `audit_log` for HOD logins, status changes, exports |
| 13 | Low | External CSS/JS without integrity checks | CSP restricts hosts; **still recommended:** self-host Tailwind/FontAwesome |

## Functional bugs

| # | Bug | Fix |
|---|-----|-----|
| 1 | Opening the Change-Password modal a second time throws a `TypeError` and the modal never opens **[verified]** (the HOD branch destroys the label element) | Both field groups exist in the HTML and are just shown/hidden |
| 2 | CSV export cut off at any `#` in text (`encodeURI` does not escape it), losing the remaining columns; description never exported **[verified]** | Server-generated CSV (Python `csv` module) with every column, UTF-8 BOM for Excel |
| 3 | Complaint IDs were random 4 digits - collisions are likely after ~100 complaints, so the HOD could edit the wrong complaint **[verified]** | Database auto-increment IDs (`AIT-00001`) |
| 4 | Diploma students could pick "4th Year" | Years depend on level, enforced in UI and server |
| 5 | HOD password was per department only - the "level" choice was cosmetic | Separate account per level + department |
| 6 | Dates stored as inconsistent locale strings (seed data used another format) | ISO timestamps in UTC, formatted in the browser |
| 7 | Password fields kept their contents after logout; passwords were `.trim()`-ed (silently changing them) | Fields cleared; passwords never altered |
| 8 | Enter key did not submit login; category typo `attendence` | Real `<form>`s; typo fixed; `alert()` replaced with toasts |

## Behaviour changes you should know about
* Tracking code is now `XXXX-XXXX-XXXX` (was 6 digits) and cannot be recovered if lost.
* Anonymous complaints show "PRN: hidden" to the HOD - HODs cannot follow up with the student.
* Students must create an account (the old "any PRN + student123" shortcut was the vulnerability).
* The original's two demo complaints are not included.

## What was NOT verified
* The Tailwind / FontAwesome / Google Fonts CDNs: my test environment had no internet, so the
  page was tested functionally (all 33 browser checks) but I could not visually confirm styling
  or that the CSP allows the Tailwind CDN script in a real browser. If the page looks unstyled,
  open the browser console (F12) and check for "Refused to ..." messages.
* HTTPS deployment, reverse proxies, and load behaviour.
