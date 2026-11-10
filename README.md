# AITRC Vita - Department HOD Grievance Portal (Flask + SQLite)

Students register a complaint for their department HOD, get a secret tracking code,
and follow its status. HODs review, update and export complaints for their own
department and level. All data is stored in a real **SQLite database** on the server.

## Run it (Windows)

Open Command Prompt **inside this folder** (type `cmd` in the File Explorer address bar):

```
python -m pip install -r requirements.txt
python app.py
```

Then open **http://127.0.0.1:5000** in your browser.

### First run - HOD registration
HOD accounts no longer get random passwords. On the first start the app creates `instance\aitrc.db` and a
**HOD setup code** (printed in the console and saved in `instance\hod_setup_code.txt`; or set your own with
the environment variable `AITRC_HOD_SETUP_CODE`).

Each HOD does this once:
1. Choose **HOD Login** -> select Level + Department -> click **New HOD? Register**
2. Enter their own password (min 8 chars), confirm it, and enter the setup code given by the administrator
3. After that they log in normally with that password, and **Change Password?** works because they know the current one.

Registration works only once per Level + Department, and is rate-limited.

**Don't want a setup code?** Start the app with the environment variable `AITRC_HOD_SETUP_CODE_REQUIRED=0`
(Windows: `set AITRC_HOD_SETUP_CODE_REQUIRED=0` then `python app.py`). The code box disappears and HODs register with
just a password. This is less secure: anyone who can open the site could register an HOD account before the real HOD does,
so register all HOD accounts yourself right after starting the app. Forgot the password? Run
`flask --app app reopen-hod-registration --level Degree --dept "Computer Science"` and the HOD registers again.

### Students
Students first select **Degree** or **Diploma**, then click **New student? Create account** and enter PRN, password, and confirm password (minimum 8 characters). The selected level is saved with the account and is required again at login. A student can submit complaints only for their registered level. Existing student accounts are migrated as **Degree** by default; update the `students.level` value in SQLite for existing Diploma accounts.

### Useful commands
```
python -m unittest -v                                   run the 48 backend tests
python -m playwright install chromium                  install browser for end-to-end tests
python e2e_test.py                                      run the 37 browser checks
flask --app app reset-hod-password --level Degree --dept "Computer Science"
flask --app app reopen-hod-registration --level Degree --dept "Computer Science"   (HOD registers again)
flask --app app reset-student-password --prn 202401001  forgotten student password
```

## Project layout
```
app.py                  Flask app: API, authentication, SQLite schema, security headers
templates/index.html    Page (no inline scripts / handlers)
static/app.js           Front-end (DOM built with textContent only)
static/app.css          Tiny fallback stylesheet
test_app.py             48 backend tests        e2e_test.py   37 browser checks
instance/               Created at runtime: aitrc.db, secret_key (keep private, never commit)
```

## Database tables
`students` (PRN, password hash) - `hods` (level, department, password hash, registered flag) -
`complaints` (hashed tracking code, scope, text, status, remarks, timestamps) -
`audit_log` (HOD logins, status changes, exports) - `rate_events` (brute-force limits).
All queries are parameterised.

## Going live (not just a demo)
* Serve over **HTTPS** and set `AITRC_HTTPS=1` (marks the session cookie `Secure`).
* Use a production server: `pip install waitress` then `waitress-serve --call app:create_app`.
* If behind a reverse proxy, make sure the app sees the real client IP (rate limits use it).
* Back up `instance\aitrc.db`. SQLite is fine for one department/college; move to PostgreSQL/MySQL
  if you expect heavy concurrent use.
* Tailwind is loaded from its CDN, which is meant for development. For production, build a
  local Tailwind CSS file and then remove `'unsafe-eval'` and the CDN from `CSP` in `app.py`.
* Self-registration means whoever registers a PRN first owns it. For stricter control, import
  the official student list and remove the `/api/register` route.
