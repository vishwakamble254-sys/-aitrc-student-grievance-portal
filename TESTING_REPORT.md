# AITRC Portal - Testing and Change Report

## Changes applied
- Added Degree/Diploma selector to Student login and registration.
- Saved the selected student level in the SQLite `students` table.
- Student login now checks PRN + selected level + password.
- Student complaint submission is restricted to the student's registered level.
- Existing databases are migrated by adding `students.level`; existing accounts default to Degree and are preserved.
- Student and HOD registration now validate `confirm_password` on the server, not only in browser JavaScript.
- HOD registration continues to require the administrator's HOD setup code when configured.
- Added backend tests for Diploma login, wrong-level login, password confirmation mismatch, and old-database migration.
- Added browser checks for the Student Degree/Diploma selector and Diploma registration/login.

## Checks run in the build environment
- `node --check static/app.js`: PASS
- `python -m py_compile app.py test_app.py e2e_test.py`: PASS
- HTML duplicate ID scan: PASS (77 IDs, no duplicates)
- Student level selector presence: PASS

## Checks not run here
- Flask backend unit/integration suite: NOT RUN because Flask/Werkzeug are not installed in this build environment and package network access is unavailable.
- Playwright browser end-to-end suite: NOT RUN because the Flask server cannot be started without Flask.
- Production HTTPS/deployment/load testing: NOT RUN.

## Run full tests on Windows
1. Extract the ZIP.
2. Open the extracted folder in VS Code.
3. Double-click `RUN_TESTS_WINDOWS.bat`, or run `python -m pip install -r requirements.txt`, `python -m unittest -v`, `python -m pip install playwright`, `python -m playwright install chromium`, and `python e2e_test.py` in the terminal.
4. A complete pass requires all 48 backend tests and all 37 browser checks to pass.

## Important migration note
Existing student accounts are assigned Degree automatically when an old database is migrated. If an existing account belongs to Diploma, its `students.level` must be changed to `Diploma` by the college database administrator before that student logs in. Back up `instance/aitrc.db` before any manual database edit.

No claim of 100% production readiness is made until the full backend and browser test suites pass on the target Windows environment and the deployment environment is tested.
