
import os
import re
import hmac
import secrets
import sqlite3

from datetime import date, datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, g, abort
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)


# ==========================================
# 1. APP CONFIGURATION
# ==========================================

app = Flask(__name__)

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "binary_brains_hospital_secret_key_2026"
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "hospital.db")

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")


DOCTORS = [
    {
        "name": "Dr. Sharma",
        "speciality": "General Physician"
    },
    {
        "name": "Dr. Yadav",
        "speciality": "Cardiologist"
    },
    {
        "name": "Dr. Singh",
        "speciality": "Dentist"
    }
]


# ==========================================
# 2. DATABASE CONNECTION
# ==========================================

def get_db():

    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row

    return g.db


@app.teardown_appcontext
def close_db(error=None):

    db = g.pop("db", None)

    if db is not None:
        db.close()


# ==========================================
# 3. DATABASE INITIALIZATION
# ==========================================

def init_db():

    db = sqlite3.connect(DATABASE)
    cursor = db.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS patients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            phone TEXT NOT NULL,
            password TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS appointments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_name TEXT NOT NULL,
            doctor_name TEXT NOT NULL,
            appointment_date TEXT NOT NULL,
            appointment_time TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending'
        )
    """)

    columns = {
        row[1] for row in
        cursor.execute(
            "PRAGMA table_info(appointments)"
        ).fetchall()
    }

    if "patient_id" not in columns:
        cursor.execute("""
            ALTER TABLE appointments
            ADD COLUMN patient_id INTEGER
        """)

    if "status" not in columns:
        cursor.execute("""
            ALTER TABLE appointments
            ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'
        """)

    cursor.execute("""
        UPDATE appointments
        SET status = 'pending'
        WHERE status IS NULL OR TRIM(status) = ''
    """)

    db.commit()
    db.close()


# ==========================================
# 4. CSRF SECURITY
# ==========================================

def generate_csrf_token():

    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)

    return session["csrf_token"]


@app.context_processor
def inject_csrf_token():

    return {
        "csrf_token": generate_csrf_token
    }


@app.before_request
def protect_post_requests():

    if request.method == "POST":

        expected = session.get("csrf_token")
        received = request.form.get("csrf_token", "")

        if not expected or not received:
            abort(400)

        if not hmac.compare_digest(
            str(expected),
            str(received)
        ):
            abort(400)


# ==========================================
# 5. LOGIN DECORATORS
# ==========================================

def patient_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if not session.get("patient_id"):
            flash("Please login first.", "error")
            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return wrapper


def admin_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if not session.get("admin_logged_in"):
            flash("Please login as admin.", "error")
            return redirect(url_for("admin_login"))

        return function(*args, **kwargs)

    return wrapper


# ==========================================
# 6. ERROR HANDLING
# ==========================================

@app.errorhandler(400)
def bad_request(error):

    return render_template(
        "error.html",
        error_title="Security Verification Failed",
        error_message=(
            "Your security token is missing or expired. "
            "Please refresh the page and try again."
        )
    ), 400


@app.errorhandler(404)
def page_not_found(error):

    return render_template(
        "error.html",
        error_title="Page Not Found",
        error_message="The requested page does not exist."
    ), 404


# ==========================================
# 7. HOME PAGE
# ==========================================

@app.route("/")
def home():

    db = get_db()

    total_doctors = len(DOCTORS)

    total_appointments = db.execute("""
        SELECT COUNT(*) FROM appointments
    """).fetchone()[0]

    return render_template(
        "index.html",
        total_doctors=total_doctors,
        total_appointments=total_appointments
    )


# ==========================================
# 8. DOCTORS PAGE
# ==========================================

@app.route("/doctors")
def doctors():

    return render_template(
        "doctors.html",
        doctors=DOCTORS
    )


# ==========================================
# 9. PATIENT REGISTRATION
# ==========================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")

        if not all([name, email, phone, password]):

            flash("Please fill in all fields.", "error")
            return redirect(url_for("register"))

        if not re.fullmatch(
            r"[^@\s]+@[^@\s]+\.[^@\s]+",
            email
        ):

            flash("Please enter a valid email.", "error")
            return redirect(url_for("register"))

        if len(password) < 8:

            flash("Password must be at least 8 characters.", "error")
            return redirect(url_for("register"))

        db = get_db()

        hashed_password = generate_password_hash(password)

        try:

            db.execute("""
                INSERT INTO patients
                (name, email, phone, password)
                VALUES (?, ?, ?, ?)
            """, (
                name,
                email,
                phone,
                hashed_password
            ))

            db.commit()

            flash(
                "Registration successful. Please login.",
                "success"
            )

            return redirect(url_for("login"))

        except sqlite3.IntegrityError:

            flash("Email already registered.", "error")
            return redirect(url_for("register"))

    return render_template("register.html")


# ==========================================
# 10. PATIENT LOGIN
# ==========================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        db = get_db()

        patient = db.execute("""
            SELECT * FROM patients
            WHERE email = ?
        """, (email,)).fetchone()

        if patient:

            try:
                valid = check_password_hash(
                    patient["password"],
                    password
                )
            except (ValueError, TypeError):
                valid = False

            if valid:

                session.clear()

                session["patient_id"] = patient["id"]
                session["patient_name"] = patient["name"]

                generate_csrf_token()

                return redirect(url_for("dashboard"))

        flash("Invalid email or password.", "error")

    return render_template("login.html")


# ==========================================
# 11. PATIENT DASHBOARD
# ==========================================

@app.route("/dashboard")
@patient_required
def dashboard():

    db = get_db()

    appointments = db.execute("""
        SELECT * FROM appointments
        WHERE patient_id = ?
        ORDER BY id DESC
    """, (session["patient_id"],)).fetchall()

    return render_template(
        "dashboard.html",
        appointments=appointments,
        patient_name=session.get("patient_name", "Patient")
    )


# ==========================================
# 12. BOOK APPOINTMENT
# ==========================================

@app.route("/book_appointment", methods=["GET", "POST"])
@app.route("/appointment", methods=["GET", "POST"])
@patient_required
def book_appointment():

    if request.method == "POST":

        doctor_name = request.form.get(
            "doctor_name", ""
        ).strip()

        appointment_date = request.form.get(
            "appointment_date", ""
        ).strip()

        appointment_time = request.form.get(
            "appointment_time", ""
        ).strip()

        if not all([
            doctor_name,
            appointment_date,
            appointment_time
        ]):

            flash("Please fill all appointment details.", "error")
            return redirect(url_for("book_appointment"))

        valid_doctors = [
            doctor["name"] for doctor in DOCTORS
        ]

        if doctor_name not in valid_doctors:

            flash("Please select a valid doctor.", "error")
            return redirect(url_for("book_appointment"))

        try:

            selected_date = date.fromisoformat(appointment_date)

            datetime.strptime(
                appointment_time,
                "%H:%M"
            )

        except ValueError:

            flash("Invalid date or time.", "error")
            return redirect(url_for("book_appointment"))

        if selected_date < date.today():

            flash("Appointment date cannot be in the past.", "error")
            return redirect(url_for("book_appointment"))

        db = get_db()

        db.execute("""
            INSERT INTO appointments (
                patient_id,
                patient_name,
                doctor_name,
                appointment_date,
                appointment_time,
                status
            )
            VALUES (?, ?, ?, ?, ?, 'pending')
        """, (
            session["patient_id"],
            session["patient_name"],
            doctor_name,
            appointment_date,
            appointment_time
        ))

        db.commit()

        flash("Appointment booked successfully!", "success")

        return redirect(url_for("my_appointments"))

    return render_template(
        "book_appointment.html",
        doctors=DOCTORS,
        today=date.today().isoformat()
    )


# ==========================================
# 13. MY APPOINTMENTS
# ==========================================

@app.route("/my_appointments")
@patient_required
def my_appointments():

    db = get_db()

    appointments = db.execute("""
        SELECT * FROM appointments
        WHERE patient_id = ?
        ORDER BY id DESC
    """, (session["patient_id"],)).fetchall()

    return render_template(
        "my_appointments.html",
        appointments=appointments
    )


# ==========================================
# 14. PATIENT LOGOUT
# ==========================================

@app.route("/logout", methods=["POST"])
@patient_required
def logout():

    session.clear()

    flash("You have been logged out.", "success")

    return redirect(url_for("home"))


# ==========================================
# 15. ADMIN LOGIN
# ==========================================

@app.route("/admin_login", methods=["GET", "POST"])
def admin_login():

    if session.get("admin_logged_in"):
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":

        username = request.form.get(
            "username", ""
        ).strip()

        password = request.form.get(
            "password", ""
        )

        username_ok = hmac.compare_digest(
            username,
            ADMIN_USERNAME
        )

        password_ok = hmac.compare_digest(
            password,
            ADMIN_PASSWORD
        )

        if username_ok and password_ok:

            session.clear()

            session["admin_logged_in"] = True

            generate_csrf_token()

            return redirect(url_for("admin_dashboard"))

        flash(
            "Invalid admin username or password.",
            "error"
        )

    return render_template("admin_login.html")


# ==========================================
# 16. ADMIN DASHBOARD
# ==========================================

@app.route("/admin")
@app.route("/admin_dashboard")
@admin_required
def admin_dashboard():

    db = get_db()

    stats = {

        "total_patients": db.execute("""
            SELECT COUNT(*) FROM patients
        """).fetchone()[0],

        "total_appointments": db.execute("""
            SELECT COUNT(*) FROM appointments
        """).fetchone()[0],

        "pending_appointments": db.execute("""
            SELECT COUNT(*) FROM appointments
            WHERE status = 'pending'
        """).fetchone()[0],

        "approved_appointments": db.execute("""
            SELECT COUNT(*) FROM appointments
            WHERE status = 'approved'
        """).fetchone()[0]
    }

    appointments = db.execute("""
        SELECT * FROM appointments
        ORDER BY id DESC
    """).fetchall()

    patients = db.execute("""
        SELECT id, name, email, phone
        FROM patients
        ORDER BY id DESC
    """).fetchall()

    return render_template(
        "admin_dashboard.html",
        stats=stats,
        appointments=appointments,
        patients=patients
    )


# ==========================================
# 17. UPDATE APPOINTMENT STATUS
# ==========================================

@app.route(
    "/update_status/<int:appointment_id>",
    methods=["POST"]
)
@admin_required
def update_status(appointment_id):

    status = request.form.get(
        "status", ""
    ).strip().lower()

    if status not in (
        "pending",
        "approved",
        "rejected"
    ):
        abort(400)

    db = get_db()

    db.execute("""
        UPDATE appointments
        SET status = ?
        WHERE id = ?
    """, (
        status,
        appointment_id
    ))

    db.commit()

    flash("Appointment status updated.", "success")

    return redirect(url_for("admin_dashboard"))


# ==========================================
# 18. DELETE APPOINTMENT
# ==========================================

@app.route(
    "/delete_appointment/<int:appointment_id>",
    methods=["POST"]
)
@admin_required
def delete_appointment(appointment_id):

    db = get_db()

    db.execute("""
        DELETE FROM appointments
        WHERE id = ?
    """, (appointment_id,))

    db.commit()

    flash("Appointment deleted.", "success")

    return redirect(url_for("admin_dashboard"))


# ==========================================
# 19. ADMIN LOGOUT
# ==========================================

@app.route("/admin_logout", methods=["POST"])
@admin_required
def admin_logout():

    session.clear()

    flash("Admin logged out.", "success")

    return redirect(url_for("admin_login"))


# ==========================================
# 20. RUN APPLICATION
# ==========================================

if __name__ == "__main__":

    init_db()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )