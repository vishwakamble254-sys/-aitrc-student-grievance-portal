"""Automated tests for the AITRC grievance portal.  Run:  python -m unittest -v"""
import csv
import io
import re
import sqlite3
import tempfile
import unittest
from pathlib import Path

from app import DEPARTMENTS, create_app

DEPT = "Computer Science"
OTHER = "Mechanical"


class Client:
    """Test client that handles the CSRF token like the browser front-end does."""

    def __init__(self, app):
        self.c = app.test_client()
        self.csrf = self.c.get("/api/session").get_json()["csrf"]

    def post(self, path, body=None, csrf=True, **kw):
        headers = {"X-CSRF-Token": self.csrf} if csrf else {}
        r = self.c.post(path, json=body or {}, headers=headers, **kw)
        j = r.get_json(silent=True) or {}
        if "csrf" in j:
            self.csrf = j["csrf"]
        return r

    def patch(self, path, body):
        return self.c.patch(path, json=body, headers={"X-CSRF-Token": self.csrf})

    def get(self, path):
        return self.c.get(path)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "test.db")
        self.app = create_app({"TESTING": True, "DATABASE": self.db, "SECRET_KEY": "test-key",
                               "HOD_SETUP_CODE": "setup-code-1",
                               "PASSWORD_HASH_METHOD": "pbkdf2:sha256:1000"})  # fast hashing for tests only
        self.hod_pw = {}  # (level, dept) -> password chosen at registration

    def tearDown(self):
        self.tmp.cleanup()

    # helpers
    def student(self, prn="202401001", pw="studentpass1"):
        cl = Client(self.app)
        r = cl.post("/api/register", {"prn": prn, "password": pw, "confirm_password": pw})
        self.assertEqual(r.status_code, 201, r.get_json())
        return cl

    def hod(self, dept=DEPT, level="Degree"):
        cl = Client(self.app)
        if (level, dept) not in self.hod_pw:  # first time: register (HOD chooses own password)
            pw = f"HodPass#{level}{dept}"[:30]
            r = cl.post("/api/register-hod", {"level": level, "dept": dept, "password": pw, "confirm_password": pw, "setup_code": "setup-code-1"})
            self.assertEqual(r.status_code, 201, r.get_json())
            self.hod_pw[(level, dept)] = pw
        r = cl.post("/api/login", {"role": "hod", "level": level, "dept": dept, "password": self.hod_pw[(level, dept)]})
        self.assertEqual(r.status_code, 200, r.get_json())
        return cl

    def complaint(self, cl, **over):
        body = {"level": "Degree", "dept": DEPT, "year": "3rd Year", "category": "teaching",
                "name": "", "subject": "Lecture speed too fast",
                "description": "The concepts are covered too fast during lectures."}
        body.update(over)
        return cl.post("/api/complaints", body)


class TestAuth(Base):
    def test_hod_accounts_start_unregistered_and_cannot_login(self):
        con = sqlite3.connect(self.db)
        self.assertEqual(con.execute("SELECT COUNT(*) FROM hods WHERE registered = 0").fetchone()[0], 2 * len(DEPARTMENTS))
        r = Client(self.app).post("/api/login", {"role": "hod", "level": "Degree", "dept": DEPT, "password": "anything123"})
        self.assertEqual(r.status_code, 403)
        self.assertIn("not registered", r.get_json()["error"])

    def test_hod_register_then_login_and_hashed(self):
        self.hod()
        con = sqlite3.connect(self.db)
        h, reg = con.execute("SELECT password_hash, registered FROM hods WHERE level='Degree' AND dept=?", (DEPT,)).fetchone()
        self.assertEqual(reg, 1)
        self.assertTrue(h.startswith("pbkdf2:"))
        self.assertNotIn(self.hod_pw[("Degree", DEPT)], h)

    def test_student_and_hod_registration_reject_password_confirmation_mismatch(self):
        cl = Client(self.app)
        student = cl.post("/api/register", {"level": "Degree", "prn": "202401888",
                                           "password": "studentpass1", "confirm_password": "different11"})
        self.assertEqual(student.status_code, 400)
        hod = cl.post("/api/register-hod", {"level": "Degree", "dept": DEPT,
                                           "password": "MyHodPass#1", "confirm_password": "Different#1",
                                           "setup_code": "setup-code-1"})
        self.assertEqual(hod.status_code, 400)

    def test_hod_register_needs_correct_setup_code(self):
        cl = Client(self.app)
        body = {"level": "Degree", "dept": DEPT, "password": "MyHodPass#1", "confirm_password": "MyHodPass#1", "setup_code": "wrong"}
        self.assertEqual(cl.post("/api/register-hod", body).status_code, 403)
        body["setup_code"] = ""
        self.assertEqual(cl.post("/api/register-hod", body).status_code, 400)
        body.update(setup_code="setup-code-1", password="short")
        self.assertEqual(cl.post("/api/register-hod", body).status_code, 400)

    def test_hod_register_without_code_when_switched_off(self):
        app = create_app({"TESTING": True, "DATABASE": str(Path(self.tmp.name) / "nocode.db"), "SECRET_KEY": "k",
                          "HOD_SETUP_CODE_REQUIRED": False, "PASSWORD_HASH_METHOD": "pbkdf2:sha256:1000"})
        cl = Client(app)
        self.assertFalse(cl.get("/api/session").get_json()["meta"]["hodCodeRequired"])
        r = cl.post("/api/register-hod", {"level": "Degree", "dept": DEPT, "password": "MyHodPass#1", "confirm_password": "MyHodPass#1"})
        self.assertEqual(r.status_code, 201, r.get_json())
        self.assertEqual(Client(app).post("/api/login", {"role": "hod", "level": "Degree", "dept": DEPT, "password": "MyHodPass#1", "confirm_password": "MyHodPass#1"}).status_code, 200)

    def test_code_required_flag_reported_to_frontend(self):
        self.assertTrue(Client(self.app).get("/api/session").get_json()["meta"]["hodCodeRequired"])

    def test_non_ascii_csrf_header_is_rejected_cleanly(self):
        cl = Client(self.app)
        r = cl.c.post("/api/login", json={}, headers={"X-CSRF-Token": "tökén"})
        self.assertEqual(r.status_code, 403)

    def test_hod_register_only_once_and_lockout(self):
        self.hod()
        body = {"level": "Degree", "dept": DEPT, "password": "Takeover#123", "confirm_password": "Takeover#123", "setup_code": "setup-code-1"}
        self.assertEqual(Client(self.app).post("/api/register-hod", body).status_code, 409)
        cl = Client(self.app)
        bad = {"level": "Degree", "dept": OTHER, "password": "MyHodPass#1", "confirm_password": "MyHodPass#1", "setup_code": "nope"}
        codes = [cl.post("/api/register-hod", bad).status_code for _ in range(6)]
        self.assertEqual(codes[-1], 429)

    def test_default_passwords_no_longer_work(self):
        self.hod()  # HOD registered with own password -> old default must not work
        cl = Client(self.app)
        r = cl.post("/api/login", {"role": "hod", "level": "Degree", "dept": DEPT, "password": "hod123"})
        self.assertEqual(r.status_code, 401)
        # unregistered PRN with the old default password
        r = cl.post("/api/login", {"role": "student", "prn": "202401001", "password": "student123"})
        self.assertEqual(r.status_code, 401)

    def test_student_degree_diploma_registration_and_level_specific_login(self):
        cl = Client(self.app)
        registered = cl.post("/api/register", {"level": "Diploma", "prn": "202405555", "password": "diplomapass1", "confirm_password": "diplomapass1"})
        self.assertEqual(registered.status_code, 201, registered.get_json())
        self.assertEqual(registered.get_json()["user"]["level"], "Diploma")
        self.assertEqual(cl.get("/api/session").get_json()["user"]["level"], "Diploma")

        wrong_level = Client(self.app).post("/api/login", {
            "role": "student", "level": "Degree", "prn": "202405555", "password": "diplomapass1"
        })
        self.assertEqual(wrong_level.status_code, 401)
        correct_level = Client(self.app).post("/api/login", {
            "role": "student", "level": "Diploma", "prn": "202405555", "password": "diplomapass1"
        })
        self.assertEqual(correct_level.status_code, 200, correct_level.get_json())

    def test_existing_student_database_migrates_to_degree(self):
        old_db = str(Path(self.tmp.name) / "old-students.db")
        con = sqlite3.connect(old_db)
        con.execute("CREATE TABLE students (prn TEXT PRIMARY KEY, password_hash TEXT NOT NULL, created_at TEXT NOT NULL)")
        con.execute("INSERT INTO students VALUES ('202401777', 'legacy-hash', '2024-01-01T00:00:00Z')")
        con.commit(); con.close()
        create_app({"TESTING": True, "DATABASE": old_db, "SECRET_KEY": "migration-key",
                    "HOD_SETUP_CODE": "setup-code-1", "PASSWORD_HASH_METHOD": "pbkdf2:sha256:1000"})
        con = sqlite3.connect(old_db)
        self.assertEqual(con.execute("SELECT level FROM students WHERE prn='202401777'").fetchone()[0], "Degree")
        con.close()

    def test_student_register_login_logout(self):
        cl = self.student()
        self.assertEqual(cl.get("/api/session").get_json()["user"]["prn"], "202401001")
        cl.post("/api/logout")
        self.assertIsNone(cl.get("/api/session").get_json()["user"])
        r = cl.post("/api/login", {"role": "student", "prn": "202401001", "password": "studentpass1"})
        self.assertEqual(r.status_code, 200)
        bad = Client(self.app).post("/api/login", {"role": "student", "prn": "202401001", "password": "wrongwrong"})
        self.assertEqual(bad.status_code, 401)

    def test_register_validation_and_duplicates(self):
        cl = Client(self.app)
        self.assertEqual(cl.post("/api/register", {"prn": "abc", "password": "studentpass1", "confirm_password": "studentpass1"}).status_code, 400)
        self.assertEqual(cl.post("/api/register", {"prn": "202401001", "password": "short", "confirm_password": "short"}).status_code, 400)
        self.student()
        self.assertEqual(Client(self.app).post("/api/register", {"prn": "202401001", "password": "otherpass12", "confirm_password": "otherpass12"}).status_code, 409)

    def test_login_lockout_after_repeated_failures(self):
        self.hod()
        cl = Client(self.app)
        codes = [cl.post("/api/login", {"role": "hod", "level": "Degree", "dept": DEPT, "password": f"bad{i}"}).status_code
                 for i in range(7)]
        self.assertEqual(codes[:5], [401] * 5)
        self.assertEqual(codes[5:], [429, 429])
        # even the right password is refused while locked out
        r = cl.post("/api/login", {"role": "hod", "level": "Degree", "dept": DEPT, "password": self.hod_pw[("Degree", DEPT)]})
        self.assertEqual(r.status_code, 429)

    def test_change_password_invalidates_other_sessions(self):
        a, b = self.student(), Client(self.app)
        b.post("/api/login", {"role": "student", "prn": "202401001", "password": "studentpass1"})
        r = a.post("/api/change-password", {"role": "student", "prn": "202401001",
                                            "old_password": "studentpass1", "new_password": "brandnewpass1"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(a.get("/api/session").get_json()["user"]["prn"], "202401001")  # changer stays in
        self.assertIsNone(b.get("/api/session").get_json()["user"])                    # other session dropped
        self.assertEqual(Client(self.app).post("/api/login", {"role": "student", "prn": "202401001", "password": "studentpass1"}).status_code, 401)
        self.assertEqual(Client(self.app).post("/api/login", {"role": "student", "prn": "202401001", "password": "brandnewpass1"}).status_code, 200)

    def test_change_password_requires_correct_old_password(self):
        self.student()
        r = Client(self.app).post("/api/change-password", {"role": "student", "prn": "202401001",
                                                          "old_password": "nope-nope-1", "new_password": "brandnewpass1"})
        self.assertEqual(r.status_code, 401)

    def test_hod_change_password_roundtrip(self):
        cl = self.hod()
        r = cl.post("/api/change-password", {"role": "hod", "level": "Degree", "dept": DEPT,
                                             "old_password": self.hod_pw[("Degree", DEPT)], "new_password": "NewHodPass#1"})
        self.assertEqual(r.status_code, 200)
        r = Client(self.app).post("/api/login", {"role": "hod", "level": "Degree", "dept": DEPT, "password": "NewHodPass#1"})
        self.assertEqual(r.status_code, 200)


class TestSecurityControls(Base):
    def test_csrf_required_on_post(self):
        cl = Client(self.app)
        r = cl.post("/api/register", {"prn": "202401001", "password": "studentpass1", "confirm_password": "studentpass1"}, csrf=False)
        self.assertEqual(r.status_code, 403)
        r = cl.c.post("/api/register", json={"prn": "202401001", "password": "studentpass1", "confirm_password": "studentpass1"}, headers={"X-CSRF-Token": "forged"})
        self.assertEqual(r.status_code, 403)

    def test_form_encoded_posts_rejected(self):
        cl = Client(self.app)
        r = cl.c.post("/api/login", data={"role": "student"}, headers={"X-CSRF-Token": cl.csrf})
        self.assertEqual(r.status_code, 415)

    def test_security_headers(self):
        for path in ("/", "/api/session"):
            r = Client(self.app).get(path)
            self.assertIn("default-src 'self'", r.headers["Content-Security-Policy"])
            self.assertNotIn("script-src 'self' 'unsafe-inline'", r.headers["Content-Security-Policy"])
            self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
            self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertEqual(Client(self.app).get("/api/session").headers["Cache-Control"], "no-store")

    def test_session_cookie_flags(self):
        r = self.app.test_client().get("/api/session")   # fresh client => cookie is issued
        cookie = r.headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)

    def test_page_has_no_inline_scripts_or_handlers(self):
        html = Client(self.app).get("/").get_data(as_text=True)
        self.assertNotRegex(html, r"<script(?![^>]*\bsrc=)[^>]*>")  # every <script> has a src
        self.assertNotRegex(html, r"\son(click|change|submit|keyup|load)\s*=")

    def test_frontend_never_uses_innerhtml(self):
        js = (Path(__file__).parent / "static" / "app.js").read_text()
        js = re.sub(r"/\*.*?\*/", "", js, flags=re.S)          # ignore comments
        js = re.sub(r"(?m)^\s*//.*$", "", js)
        self.assertNotIn("innerHTML", js)
        self.assertNotIn("eval(", js)
        self.assertNotIn("localStorage", js)

    def test_unauthenticated_and_wrong_role_access(self):
        anon = Client(self.app)
        self.assertEqual(anon.get("/api/hod/complaints").status_code, 401)
        self.assertEqual(anon.get("/api/hod/export").status_code, 401)
        self.assertEqual(anon.post("/api/complaints", {}).status_code, 401)
        self.assertEqual(anon.post("/api/track", {"pin": "AAAA-BBBB-CCCC"}).status_code, 401)
        stu = self.student()
        self.assertEqual(stu.get("/api/hod/complaints").status_code, 403)
        self.assertEqual(stu.patch("/api/hod/complaints/1", {"status": "Resolved"}).status_code, 403)
        hod = self.hod()
        self.assertEqual(hod.post("/api/complaints", {}).status_code, 403)

    def test_forged_session_cookie_cannot_become_hod(self):
        cl = Client(self.app)
        with cl.c.session_transaction() as s:   # even with a *valid signature*, role must match the DB
            s["role"] = "hod"; s["hod_id"] = 1; s["fp"] = "forged"
        self.assertEqual(cl.get("/api/hod/complaints").status_code, 401)

    def test_sql_injection_attempts(self):
        cl = Client(self.app)
        r = cl.post("/api/login", {"role": "student", "prn": "' OR '1'='1", "password": "' OR '1'='1"})
        self.assertEqual(r.status_code, 401)
        stu = self.student()
        r = self.complaint(stu, name="Robert'); DROP TABLE complaints;--", subject="x' OR 1=1 --")
        self.assertEqual(r.status_code, 201)
        hod = self.hod()
        for q in ("' OR 1=1 --", "%", "_", "\\", "a' UNION SELECT password_hash FROM hods --"):
            r = hod.get("/api/hod/complaints?q=" + q)
            self.assertEqual(r.status_code, 200, q)
        self.assertEqual(len(hod.get("/api/hod/complaints?q=%25").get_json()["complaints"]), 0)  # '%' is literal
        self.assertEqual(len(hod.get("/api/hod/complaints").get_json()["complaints"]), 1)       # table intact

    def test_oversized_body_rejected(self):
        cl = Client(self.app)
        r = cl.post("/api/register", {"prn": "202401001", "password": "x" * 100000, "confirm_password": "x" * 100000})
        self.assertEqual(r.status_code, 413)


class TestComplaints(Base):
    def test_student_cannot_submit_complaint_for_other_study_level(self):
        cl = Client(self.app)
        r = cl.post("/api/register", {"level": "Diploma", "prn": "202406666",
                                    "password": "diplomapass1", "confirm_password": "diplomapass1"})
        self.assertEqual(r.status_code, 201)
        denied = self.complaint(cl, level="Degree")
        self.assertEqual(denied.status_code, 403)
        allowed = self.complaint(cl, level="Diploma", year="2nd Year")
        self.assertEqual(allowed.status_code, 201, allowed.get_json())

    def test_submit_and_track_roundtrip(self):
        stu = self.student()
        r = self.complaint(stu, name="Rahul Patil")
        self.assertEqual(r.status_code, 201)
        j = r.get_json()
        self.assertRegex(j["pin"], r"^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$")
        self.assertRegex(j["ref"], r"^AIT-\d{5}$")
        t = stu.post("/api/track", {"pin": j["pin"].lower().replace("-", " ")})  # forgiving input
        self.assertEqual(t.status_code, 200)
        self.assertEqual(t.get_json()["subject"], "Lecture speed too fast")
        self.assertNotIn("student_prn", t.get_json())

    def test_pin_is_not_stored_in_clear(self):
        stu = self.student()
        pin = self.complaint(stu).get_json()["pin"]
        raw = sqlite3.connect(self.db).execute("SELECT pin_hash FROM complaints").fetchone()[0]
        self.assertNotIn(pin.replace("-", ""), raw)
        self.assertEqual(len(raw), 64)

    def test_unique_refs_and_pins(self):
        stu = self.student()
        results = [self.complaint(stu).get_json() for _ in range(8)]
        self.assertEqual(len({r["ref"] for r in results}), 8)
        self.assertEqual(len({r["pin"] for r in results}), 8)

    def test_anonymous_complaint_does_not_store_prn(self):
        stu = self.student()
        self.complaint(stu, name="")
        row = sqlite3.connect(self.db).execute("SELECT student_prn, student_name FROM complaints").fetchone()
        self.assertEqual(row, (None, None))
        item = self.hod().get("/api/hod/complaints").get_json()["complaints"][0]
        self.assertEqual(item["student_name"], "Anonymous")
        self.assertIsNone(item["student_prn"])

    def test_named_complaint_stores_prn(self):
        stu = self.student()
        self.complaint(stu, name="Rahul Patil")
        item = self.hod().get("/api/hod/complaints").get_json()["complaints"][0]
        self.assertEqual((item["student_name"], item["student_prn"]), ("Rahul Patil", "202401001"))

    def test_wrong_pin_404_and_rate_limited(self):
        stu = self.student()
        codes = [stu.post("/api/track", {"pin": f"AAAA-BBBB-CC{i:02d}".replace("0", "2").replace("1", "3")}).status_code for i in range(12)]
        self.assertEqual(codes[:10], [404] * 10)
        self.assertEqual(codes[10:], [429, 429])

    def test_validation_rules(self):
        stu = self.student()
        self.assertEqual(self.complaint(stu, level="Diploma", year="4th Year").status_code, 400)  # diploma has 3 years
        self.assertEqual(self.complaint(stu, level="Diploma", year="3rd Year").status_code, 201)
        self.assertEqual(self.complaint(stu, dept="Fake Dept").status_code, 400)
        self.assertEqual(self.complaint(stu, category="nope").status_code, 400)
        self.assertEqual(self.complaint(stu, subject="").status_code, 400)
        self.assertEqual(self.complaint(stu, subject="x" * 151).status_code, 400)
        self.assertEqual(self.complaint(stu, description="short").status_code, 400)
        self.assertEqual(self.complaint(stu, description="d" * 3001).status_code, 400)
        self.assertEqual(self.complaint(stu, subject=["list"]).status_code, 400)
        self.assertEqual(self.complaint(stu, category="others").status_code, 400)                      # needs custom_text
        self.assertEqual(self.complaint(stu, category="others", custom_text="Library hours").status_code, 201)

    def test_xss_payload_is_stored_verbatim_and_served_as_json(self):
        payload = '<img src=x onerror=alert(1)><script>alert(2)</script>'
        stu = self.student()
        self.assertEqual(self.complaint(stu, subject=payload, description=payload + " more text", name=payload).status_code, 201)
        r = self.hod().get("/api/hod/complaints")
        self.assertEqual(r.mimetype, "application/json")   # never rendered as HTML by the server
        self.assertEqual(r.get_json()["complaints"][0]["subject"], payload)  # escaping is done by the front-end (textContent)

    def test_submit_rate_limit(self):
        stu = self.student()
        codes = [self.complaint(stu).status_code for _ in range(12)]
        self.assertEqual(codes[:10], [201] * 10)
        self.assertEqual(codes[10:], [429, 429])

    def test_control_characters_stripped(self):
        stu = self.student()
        self.complaint(stu, subject="Hello\x00 \x07World\r\nSecond line")
        subject = self.hod().get("/api/hod/complaints").get_json()["complaints"][0]["subject"]
        self.assertEqual(subject, "Hello World Second line")


class TestHod(Base):
    def test_hod_sees_only_own_department_and_level(self):
        stu = self.student()
        self.complaint(stu, dept=DEPT, subject="CS degree issue")
        self.complaint(stu, dept=OTHER, subject="Mech degree issue")
        self.complaint(stu, dept=DEPT, level="Diploma", year="2nd Year", subject="CS diploma issue")
        cs = self.hod(DEPT, "Degree").get("/api/hod/complaints").get_json()
        self.assertEqual([c["subject"] for c in cs["complaints"]], ["CS degree issue"])
        self.assertEqual(cs["stats"]["total"], 1)
        mech = self.hod(OTHER, "Degree").get("/api/hod/complaints").get_json()
        self.assertEqual([c["subject"] for c in mech["complaints"]], ["Mech degree issue"])

    def test_hod_cannot_update_other_departments_complaint(self):
        stu = self.student()
        self.complaint(stu, dept=OTHER)
        cs_hod = self.hod(DEPT, "Degree")
        r = cs_hod.patch("/api/hod/complaints/1", {"status": "Resolved", "remarks": "hijack"})
        self.assertEqual(r.status_code, 404)
        status = sqlite3.connect(self.db).execute("SELECT status, remarks FROM complaints").fetchone()
        self.assertEqual(status, ("Pending", ""))

    def test_update_status_and_remarks_visible_to_student(self):
        stu = self.student()
        pin = self.complaint(stu).get_json()["pin"]
        hod = self.hod()
        self.assertEqual(hod.patch("/api/hod/complaints/1", {"status": "In Progress", "remarks": "Discussed with faculty."}).status_code, 200)
        t = stu.post("/api/track", {"pin": pin}).get_json()
        self.assertEqual((t["status"], t["remarks"]), ("In Progress", "Discussed with faculty."))
        self.assertEqual(hod.get("/api/hod/complaints").get_json()["stats"]["in_progress"], 1)

    def test_invalid_status_rejected(self):
        stu = self.student(); self.complaint(stu)
        self.assertEqual(self.hod().patch("/api/hod/complaints/1", {"status": "Hacked"}).status_code, 400)

    def test_filter_and_search(self):
        stu = self.student()
        self.complaint(stu, subject="Projector broken", category="classroom issue", name="Asha")
        self.complaint(stu, subject="Attendance wrongly marked", category="attendance issue")
        hod = self.hod()
        hod.patch("/api/hod/complaints/1", {"status": "Resolved", "remarks": ""})
        count = lambda q: len(hod.get("/api/hod/complaints?" + q).get_json()["complaints"])
        self.assertEqual(count("status=Resolved"), 1)
        self.assertEqual(count("status=Pending"), 1)
        self.assertEqual(count("q=projector"), 1)
        self.assertEqual(count("q=AIT-00002"), 1)
        self.assertEqual(count("q=anonymous"), 1)
        self.assertEqual(count("q=202401001"), 1)  # matches only the named complaint
        self.assertEqual(hod.get("/api/hod/complaints?status=bogus").status_code, 400)

    def test_csv_export_scoped_complete_and_formula_safe(self):
        stu = self.student()
        self.complaint(stu, subject="=HYPERLINK(\"http://evil\",\"x\")", description="Line one\nLine two, with # and \"quotes\"", name="+cmd")
        self.complaint(stu, dept=OTHER, subject="Other dept secret")
        r = self.hod().get("/api/hod/export")
        self.assertEqual(r.status_code, 200)
        self.assertIn("attachment", r.headers["Content-Disposition"])
        text = r.get_data(as_text=True).lstrip("\ufeff")
        self.assertNotIn("Other dept secret", text)
        rows = list(csv.reader(io.StringIO(text)))
        self.assertEqual(len(rows), 2)
        header, row = rows
        rec = dict(zip(header, row))
        self.assertEqual(rec["Subject"][0], "'")                 # formula neutralised
        self.assertEqual(rec["Student Name"][0], "'")
        self.assertIn("Line two, with # and \"quotes\"", rec["Description"])  # '#' no longer truncates the file

    def test_hod_actions_are_audited(self):
        stu = self.student(); self.complaint(stu)
        hod = self.hod()
        hod.patch("/api/hod/complaints/1", {"status": "Resolved", "remarks": "done"})
        hod.get("/api/hod/export")
        actions = [a for (a,) in sqlite3.connect(self.db).execute("SELECT action FROM audit_log")]
        self.assertEqual(actions, ["register", "login", "update_complaint", "export_csv"])


class TestCli(Base):
    def test_reset_commands(self):
        self.student()
        runner = self.app.test_cli_runner()
        r = runner.invoke(args=["reset-student-password", "--prn", "202401001", "--password", "resetpass123"])
        self.assertIn("new password: resetpass123", r.output)
        self.assertEqual(Client(self.app).post("/api/login", {"role": "student", "prn": "202401001", "password": "resetpass123"}).status_code, 200)
        r = runner.invoke(args=["reset-hod-password", "--level", "Degree", "--dept", DEPT, "--password", "HodReset#123"])
        self.assertIn("new password: HodReset#123", r.output)
        self.assertEqual(Client(self.app).post("/api/login", {"role": "hod", "level": "Degree", "dept": DEPT, "password": "HodReset#123"}).status_code, 200)
        r = runner.invoke(args=["reopen-hod-registration", "--level", "Degree", "--dept", DEPT])
        self.assertIn("1 HOD account(s) reopened", r.output)
        self.assertEqual(Client(self.app).post("/api/login", {"role": "hod", "level": "Degree", "dept": DEPT, "password": "HodReset#123"}).status_code, 403)
        self.hod_pw.pop(("Degree", DEPT), None)
        self.hod()  # registers again with a new password


class TestPersistence(Base):
    def test_data_survives_restart(self):
        stu = self.student()
        pin = self.complaint(stu, name="Persist Me").get_json()["pin"]
        app2 = create_app({"TESTING": True, "DATABASE": self.db, "SECRET_KEY": "test-key", "HOD_SETUP_CODE": "setup-code-1",
                           "PASSWORD_HASH_METHOD": "pbkdf2:sha256:1000"})
        self.assertEqual(Client(app2).post("/api/register-hod", {"level": "Degree", "dept": DEPT, "password": "Another#123", "confirm_password": "Another#123", "setup_code": "setup-code-1"}).status_code, 201)
        cl = Client(app2)
        cl.post("/api/login", {"role": "student", "prn": "202401001", "password": "studentpass1"})
        self.assertEqual(cl.post("/api/track", {"pin": pin}).get_json()["subject"], "Lecture speed too fast")

    def test_session_meta_contains_dropdown_data(self):
        meta = Client(self.app).get("/api/session").get_json()["meta"]
        self.assertEqual(meta["years"]["Diploma"], ["1st Year", "2nd Year", "3rd Year"])
        self.assertEqual(len(meta["departments"]), 7)


if __name__ == "__main__":
    unittest.main()
