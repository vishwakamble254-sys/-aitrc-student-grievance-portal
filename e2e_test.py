"""
Optional browser end-to-end test (needs:  pip install playwright && playwright install chromium).
Run:  python e2e_test.py
It starts the app on a temporary database, drives the real UI, and checks the security fixes.
External CDNs are blocked in this test, so only functionality (not Tailwind styling) is exercised.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

PORT = 5077
BASE = f"http://127.0.0.1:{PORT}"
XSS = '<img src=x onerror="window.__pwned=1"><b>bold</b>'
tmp = tempfile.mkdtemp()
SETUP_CODE = "e2e-setup-code"
HOD_PW = "MyHodPass#2026"

server_code = f"""
import json, sys
from app import create_app
app = create_app({{"DATABASE": r"{tmp}/e2e.db", "SECRET_KEY": "e2e", "HOD_SETUP_CODE": "e2e-setup-code",
                  "PASSWORD_HASH_METHOD": "pbkdf2:sha256:1000"}})
app.run(host="127.0.0.1", port={PORT})
"""
proc = subprocess.Popen([sys.executable, "-c", server_code], cwd=Path(__file__).parent)
for _ in range(50):
    try:
        urllib.request.urlopen(BASE + "/api/session"); break
    except Exception:
        time.sleep(0.2)

results = []
def check(name, cond, extra=""):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if (extra and not cond) else ""))

try:
    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context(accept_downloads=True)
        page = ctx.new_page()
        errors, dialogs = [], []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.on("console", lambda m: errors.append(m.text) if m.type == "error" and "Failed to load resource" not in m.text and "ERR_" not in m.text else None)
        page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))
        page.route("**/*", lambda r: r.continue_() if r.request.url.startswith(BASE) else r.abort())

        def toast():
            return page.locator("#toast-container").inner_text()

        page.goto(BASE)
        page.wait_for_selector("#view-login:not(.hidden)")
        check("login view visible, others hidden", page.locator("#view-student.hidden").count() == 1 and page.locator("#view-hod.hidden").count() == 1)
        check("dropdowns populated from API", page.locator("#hod-dept-select option").count() == 7 and page.locator("#c-category option").count() == 7 and page.locator("#student-level-select option").count() == 2)

        # --- student registration
        page.select_option("#student-level-select", "Degree")
        page.click("#toggle-register-btn")
        check("register mode shows confirm field", page.locator("#student-confirm-group:not(.hidden)").count() == 1)
        page.fill("#student-prn-input", "202401001"); page.fill("#student-pass-input", "studentpass1"); page.fill("#student-confirm-input", "different11")
        page.click("#login-submit-btn"); page.wait_for_timeout(300)
        check("mismatched passwords rejected", "do not match" in toast())
        page.fill("#student-confirm-input", "studentpass1"); page.click("#login-submit-btn")
        page.wait_for_selector("#view-student:not(.hidden)")
        check("registered + logged in as student", "202401001" in page.locator("#nav-auth-section").inner_text())
        check("password fields cleared after login", page.locator("#student-pass-input").input_value() == "")

        # --- form behaviour
        page.select_option("#c-level", "Diploma")
        years = page.locator("#c-year option").all_inner_texts()
        check("Diploma has no 4th Year", not any("4th" in y for y in years), years)
        page.select_option("#c-level", "Degree")
        check("Degree has 4th Year", any("4th" in y for y in page.locator("#c-year option").all_inner_texts()))
        page.select_option("#c-category", "others")
        check("custom issue field shown for 'others'", page.locator("#custom-category-container:not(.hidden)").count() == 1)
        page.select_option("#c-category", "teaching")
        check("custom issue field hidden again", page.locator("#custom-category-container.hidden").count() == 1)

        # --- submit complaint with an XSS payload (named)
        page.select_option("#c-dept", "Computer Science"); page.select_option("#c-year", "3rd Year")
        page.fill("#c-name", XSS); page.fill("#c-subject", XSS); page.fill("#c-desc", "Description " + XSS + " plus more text")
        page.click("#complaint-form button[type=submit]")
        page.wait_for_selector("#modal-success:not(.hidden)")
        pin = page.locator("#modal-pin-display").inner_text()
        check("tracking code shown (XXXX-XXXX-XXXX)", len(pin) == 14 and pin.count("-") == 2, pin)
        page.click("[data-action=close-success]")
        check("closing modal opens Track tab", page.locator("#student-tab-track:not(.hidden)").count() == 1)

        # --- second, anonymous complaint
        page.click("#tab-btn-submit")
        page.select_option("#c-level", "Degree"); page.select_option("#c-dept", "Computer Science"); page.select_option("#c-year", "2nd Year")
        page.select_option("#c-category", "personal issue"); page.fill("#c-custom-text", "Lab timing clash")
        page.fill("#c-subject", "Anonymous subject"); page.fill("#c-desc", "An anonymous description that is long enough.")
        page.click("#complaint-form button[type=submit]"); page.wait_for_selector("#modal-success:not(.hidden)")
        page.click("[data-action=close-success]")

        # --- track
        page.fill("#track-pin-input", pin.lower()); page.click("#track-form button[type=submit]")
        page.wait_for_selector("#track-result-container h4")
        check("tracking shows subject as literal text", page.locator("#track-result-container h4").inner_text() == XSS)
        check("no <img>/<b> injected in tracking result", page.locator("#track-result-container img, #track-result-container b").count() == 0)
        page.fill("#track-pin-input", "AAAA-BBBB-CCCC"); page.click("#track-form button[type=submit]")
        page.wait_for_selector("text=Complaint Not Found")
        check("wrong code shows not-found", True)

        # --- logout + wrong HOD password
        page.click("[data-action=logout]"); page.wait_for_selector("#view-login:not(.hidden)")
        check("logout returns to login & clears form", page.locator("#student-pass-input").input_value() == "")
        page.select_option("#login-role", "hod")
        page.fill("#hod-pass-input", "hod123"); page.click("#login-submit-btn"); page.wait_for_timeout(300)
        check("unregistered HOD cannot log in", "not registered" in toast())

        # --- change-password modal regression (original bug: student modal showed department select after HOD modal)
        page.click("#hod-login-container [data-action=open-change-password]")
        check("HOD change-password shows level+dept", page.locator("#cp-hod-group:not(.hidden)").count() == 1 and page.locator("#cp-student-group.hidden").count() == 1)
        page.click("[data-action=close-change-password]")
        page.select_option("#login-role", "student")
        page.click("#student-login-container [data-action=open-change-password][data-type=student]")
        check("student change-password shows PRN field after HOD modal", page.locator("#cp-student-group:not(.hidden)").count() == 1 and page.locator("#cp-hod-group.hidden").count() == 1)
        page.click("[data-action=close-change-password]")

        # --- HOD login
        page.select_option("#login-role", "hod")
        page.select_option("#hod-level-select", "Degree"); page.select_option("#hod-dept-select", "Computer Science")
        page.click("#toggle-hod-register-btn")  # first-time HOD registration
        page.fill("#hod-pass-input", HOD_PW); page.fill("#hod-confirm-input", HOD_PW)
        page.fill("#hod-code-input", "wrong-code"); page.click("#login-submit-btn"); page.wait_for_timeout(300)
        check("wrong HOD setup code rejected", "Invalid HOD setup code" in toast())
        page.fill("#hod-code-input", SETUP_CODE); page.click("#login-submit-btn")
        page.wait_for_selector("#view-hod:not(.hidden)"); page.wait_for_selector("#hod-table-body tr")
        check("HOD dashboard lists both complaints", page.locator("#hod-table-body tr").count() == 2)
        check("stats: total 2 / pending 2", page.locator("#stat-total").inner_text() == "2" and page.locator("#stat-pending").inner_text() == "2")
        body_html = page.locator("#hod-table-body").inner_html()
        check("XSS payload escaped in HOD table (no live <img>)", page.locator("#hod-table-body img").count() == 0 and "&lt;img" in body_html)
        check("anonymous complaint hides PRN", "hidden (anonymous)" in page.locator("#hod-table-body").inner_text())
        check("custom issue title shown in category", "personal issue: Lab timing clash" in page.locator("#hod-table-body").inner_text())

        # --- search
        page.fill("#search-input", "Anonymous subject"); page.wait_for_timeout(700)
        check("search narrows to 1 row", page.locator("#hod-table-body tr").count() == 1)
        page.fill("#search-input", ""); page.wait_for_timeout(700)

        # --- update complaint
        page.locator("#hod-table-body tr", has_text="202401001").locator("[data-action=open-detail]").click()
        page.wait_for_selector("#modal-detail:not(.hidden)")
        check("detail modal shows payload as text", page.locator("#detail-subject").inner_text() == XSS and page.locator("#modal-detail img").count() == 0)
        page.select_option("#detail-status", "Resolved"); page.fill("#detail-remarks", "Spoke to faculty.\nResolved.")
        page.click("[data-action=save-detail]"); page.wait_for_timeout(600)
        check("stats updated after save", page.locator("#stat-resolved").inner_text() == "1" and page.locator("#stat-pending").inner_text() == "1")
        page.click("#filter-btn-Resolved"); page.wait_for_timeout(500)
        check("status filter works", page.locator("#hod-table-body tr").count() == 1)
        page.click("#filter-btn-all")

        # --- export
        with page.expect_download() as dl:
            page.click("[data-action=export]")
        csv_text = Path(dl.value.path()).read_text(encoding="utf-8")
        check("CSV export downloaded with description + remarks", "Spoke to faculty." in csv_text and "Description" in csv_text.splitlines()[0])

        # --- student sees update
        page.click("[data-action=logout]")
        page.select_option("#login-role", "student")
        page.fill("#student-prn-input", "202401001"); page.fill("#student-pass-input", "studentpass1"); page.click("#login-submit-btn")
        page.wait_for_selector("#view-student:not(.hidden)"); page.click("#tab-btn-track")
        page.fill("#track-pin-input", pin); page.click("#track-form button[type=submit]")
        page.wait_for_selector("#track-result-container h4")
        txt = page.locator("#track-result-container").inner_text()
        check("student sees Resolved + HOD remarks", "Resolved" in txt and "Spoke to faculty." in txt)

        # --- Diploma student level is stored and required at login
        page.click("[data-action=logout]"); page.wait_for_selector("#view-login:not(.hidden)")
        page.select_option("#student-level-select", "Diploma")
        page.click("#toggle-register-btn")
        page.fill("#student-prn-input", "202405555"); page.fill("#student-pass-input", "diplomapass1")
        page.fill("#student-confirm-input", "diplomapass1"); page.click("#login-submit-btn")
        page.wait_for_selector("#view-student:not(.hidden)")
        check("Diploma student registration stores Diploma level", "Diploma" in page.locator("#nav-auth-section").inner_text())
        page.click("[data-action=logout]"); page.wait_for_selector("#view-login:not(.hidden)")
        page.select_option("#student-level-select", "Degree")
        page.fill("#student-prn-input", "202405555"); page.fill("#student-pass-input", "diplomapass1"); page.click("#login-submit-btn"); page.wait_for_timeout(300)
        check("Diploma student cannot log in using Degree selection", "Invalid credentials" in toast())
        page.select_option("#student-level-select", "Diploma"); page.click("#login-submit-btn")
        page.wait_for_selector("#view-student:not(.hidden)")
        check("Diploma student logs in using Diploma selection", "Diploma" in page.locator("#nav-auth-section").inner_text())

        check("no XSS executed (window.__pwned unset)", page.evaluate("window.__pwned") is None)
        check("no alert()/confirm() dialogs used", dialogs == [], dialogs)
        check("no JS errors / CSP violations in console", errors == [], errors)
        browser.close()
finally:
    proc.terminate()

failed = [n for n, ok in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} browser checks passed")
sys.exit(1 if failed else 0)
