from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
from functools import wraps

app = Flask(__name__)
app.secret_key = "change_this_to_a_random_secret_key"
app.permanent_session_lifetime = timedelta(days=7)  # parent stays logged in


# =================== DATABASE HELPERS ===================

def get_db_connection():
    conn = sqlite3.connect("leaves.db")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    cur = conn.cursor()

    # Users table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT NOT NULL,
            password   TEXT NOT NULL,
            role       TEXT NOT NULL,   -- student / parent / advisor / warden / admin
            student_id INTEGER          -- used for student & parent
        )
    """)

    # Leave requests table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS leave_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id       INTEGER NOT NULL,
            reason           TEXT    NOT NULL,
            start_date       TEXT    NOT NULL,
            end_date         TEXT    NOT NULL,
            status           TEXT    NOT NULL,
            parent_approved  INTEGER DEFAULT 0,
            advisor_approved INTEGER DEFAULT 0,
            warden_approved  INTEGER DEFAULT 0,
            created_at       TEXT    DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Default admin
    cur.execute("SELECT * FROM users WHERE role='admin'")
    admin = cur.fetchone()
    if not admin:
        cur.execute(
            "INSERT INTO users (username, password, role, student_id) VALUES (?, ?, 'admin', NULL)",
            ("admin", generate_password_hash("admin123"))
        )
        print("Default admin created: username=admin, password=admin123")

    conn.commit()
    conn.close()


# Initialize DB once when app starts (Flask 3 safe)
with app.app_context():
    init_db()


# =================== LOGIN PROTECTOR ===================

def login_required(role=None):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("index"))
            if role and session.get("role") != role:
                flash("You are not allowed to access that page.")
                return redirect(url_for("index"))
            return func(*args, **kwargs)
        return wrapper
    return decorator


# =================== HOME + MODULE PAGES ===================

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/student")
def student_portal():
    return render_template("student_portal.html")


@app.route("/parent")
def parent_portal():
    return render_template("parent_portal.html")


@app.route("/advisor")
def advisor_portal():
    return render_template("advisor_portal.html")


@app.route("/warden")
def warden_portal():
    return render_template("warden_portal.html")


@app.route("/admin-portal")
def admin_portal():
    return render_template("admin_portal.html")


# =================== STUDENT AUTH & DASHBOARD ===================

@app.route("/register/student", methods=["GET", "POST"])
def register_student():
    if request.method == "POST":
        student_id = request.form.get("student_id", "").strip()
        password = request.form.get("password", "").strip()

        if not student_id.isdigit():
            flash("Student ID must contain only numbers.")
            return redirect(url_for("register_student"))
        if not password:
            flash("Password cannot be empty.")
            return redirect(url_for("register_student"))

        if len(password) < 6 or len(password) > 12:
            flash("Password must be 6–12 characters long.")
            return redirect(url_for("register_student"))

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("SELECT * FROM users WHERE role='student' AND student_id=?", (student_id,))
        existing = cur.fetchone()
        if existing:
            flash("Student already registered, please login.")
            conn.close()
            return redirect(url_for("login_student"))

        cur.execute(
            "INSERT INTO users (username, password, role, student_id) VALUES (?, ?, 'student', ?)",
            (f"Student {student_id}", generate_password_hash(password), student_id)
        )
        conn.commit()
        conn.close()

        flash("Student registered successfully. Please login.")
        return redirect(url_for("login_student"))

    return render_template("register_student.html")


@app.route("/login/student", methods=["GET", "POST"])
def login_student():
    if request.method == "POST":
        student_id = request.form.get("student_id", "").strip()
        password = request.form.get("password", "")

        if not student_id.isdigit():
            flash("Student ID must be numbers only.")
            return redirect(url_for("login_student"))

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE role='student' AND student_id=?", (student_id,))
        user = cur.fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["role"] = "student"
            session["student_id"] = user["student_id"]
            session["username"] = user["username"]
            session.permanent = False
            return redirect(url_for("student_dashboard"))

        flash("Invalid student ID or password.")
        return redirect(url_for("login_student"))

    return render_template("login_student.html")


@app.route("/dashboard/student")
@login_required(role="student")
def student_dashboard():
    student_id = session.get("student_id")
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM leave_requests WHERE student_id=? ORDER BY created_at DESC",
        (student_id,)
    )
    leaves = cur.fetchall()
    conn.close()
    return render_template("student_dashboard.html", leaves=leaves)


@app.route("/apply_leave", methods=["GET", "POST"])
@login_required(role="student")
def apply_leave():
    if request.method == "POST":
        student_id = session.get("student_id")
        reason = request.form.get("reason", "").strip()
        start_date = request.form.get("start_date", "").strip()
        end_date = request.form.get("end_date", "").strip()

        if not reason or not start_date or not end_date:
            flash("All fields are required.")
            return redirect(url_for("apply_leave"))

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO leave_requests (
                student_id, reason, start_date, end_date, status,
                parent_approved, advisor_approved, warden_approved
            )
            VALUES (?, ?, ?, ?, 'Pending Parent Approval', 0, 0, 0)
        """, (student_id, reason, start_date, end_date))
        conn.commit()
        conn.close()

        flash("Leave application submitted. Waiting for parent approval.")
        return redirect(url_for("student_dashboard"))

    return render_template("apply_leave.html")


# =================== PARENT AUTH & DASHBOARD ===================

@app.route("/register/parent", methods=["GET", "POST"])
def register_parent():
    if request.method == "POST":
        student_id = request.form.get("student_id", "").strip()
        password = request.form.get("password", "").strip()

        if not student_id.isdigit():
            flash("Student ID must be numbers only.")
            return redirect(url_for("register_parent"))
        if not password:
            flash("Password cannot be empty.")
            return redirect(url_for("register_parent"))

        # ✅ Password length restriction
        if len(password) < 6 or len(password) > 12:
            flash("Password must be 6–12 characters long.")
            return redirect(url_for("register_parent"))

        conn = get_db_connection()
        cur = conn.cursor()

        # child must exist
        cur.execute("SELECT * FROM users WHERE role='student' AND student_id=?", (student_id,))
        student = cur.fetchone()
        if not student:
            flash("No student found with this ID. Ask your child to register first.")
            conn.close()
            return redirect(url_for("register_parent"))

        cur.execute(
            "INSERT INTO users (username, password, role, student_id) VALUES (?, ?, 'parent', ?)",
            (f"Parent of {student_id}", generate_password_hash(password), student_id)
        )
        conn.commit()
        conn.close()

        flash("Parent registered successfully. Please login.")
        return redirect(url_for("login_parent"))

    return render_template("register_parent.html")


@app.route("/login/parent", methods=["GET", "POST"])
def login_parent():
    if request.method == "POST":
        student_id = request.form.get("student_id", "").strip()
        password = request.form.get("password", "")

        if not student_id.isdigit():
            flash("Student ID must be numbers only.")
            return redirect(url_for("login_parent"))

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE role='parent' AND student_id=?", (student_id,))
        parent = cur.fetchone()
        conn.close()

        if parent and check_password_hash(parent["password"], password):
            session["user_id"] = parent["id"]
            session["role"] = "parent"
            session["student_id"] = parent["student_id"]  # child id
            session["username"] = parent["username"]
            session.permanent = True  # parent stays logged in across sessions
            return redirect(url_for("parent_dashboard"))

        flash("Invalid student ID or password.")
        return redirect(url_for("login_parent"))

    return render_template("login_parent.html")


@app.route("/dashboard/parent")
@login_required(role="parent")
def parent_dashboard():
    student_id = session.get("student_id")

    conn = get_db_connection()
    cur = conn.cursor()

    # All leaves of this child
    cur.execute(
        "SELECT * FROM leave_requests WHERE student_id=? ORDER BY created_at DESC",
        (student_id,)
    )
    leaves = cur.fetchall()

    # Notifications = how many are waiting for parent action
    cur.execute("""
        SELECT COUNT(*) AS pending
        FROM leave_requests
        WHERE student_id=? AND parent_approved=0 AND status='Pending Parent Approval'
    """, (student_id,))
    pending_count = cur.fetchone()["pending"]

    conn.close()

    return render_template("parent_dashboard.html", leaves=leaves, pending_count=pending_count)


@app.route("/parent/approve/<int:leave_id>", methods=["POST"])
@login_required(role="parent")
def parent_approve(leave_id):
    action = request.form.get("action")
    student_id = session.get("student_id")

    conn = get_db_connection()
    cur = conn.cursor()

    # ensure this leave belongs to this parent's child
    cur.execute("""
        SELECT * FROM leave_requests
        WHERE id=? AND student_id=? AND status='Pending Parent Approval'
    """, (leave_id, student_id))
    leave = cur.fetchone()

    if not leave:
        flash("Leave not found or already processed.")
        conn.close()
        return redirect(url_for("parent_dashboard"))

    if action == "approve":
        cur.execute("""
            UPDATE leave_requests
            SET parent_approved=1,
                status='Pending Advisor Approval'
            WHERE id=?
        """, (leave_id,))
        flash("Leave approved and sent to advisor.")
    else:
        cur.execute("""
            UPDATE leave_requests
            SET parent_approved=0,
                status='Rejected by Parent'
            WHERE id=?
        """, (leave_id,))
        flash("Leave rejected by parent.")

    conn.commit()
    conn.close()
    return redirect(url_for("parent_dashboard"))


# =================== ADVISOR AUTH & DASHBOARD ===================

@app.route("/register/advisor", methods=["GET", "POST"])
def register_advisor():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            flash("All fields are required.")
            return redirect(url_for("register_advisor"))

        # ✅ Password length restriction
        if len(password) < 6 or len(password) > 12:
            flash("Password must be 6–12 characters long.")
            return redirect(url_for("register_advisor"))

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("SELECT * FROM users WHERE role='advisor' AND username=?", (username,))
        existing = cur.fetchone()
        if existing:
            flash("Advisor username already exists.")
            conn.close()
            return redirect(url_for("register_advisor"))

        cur.execute(
            "INSERT INTO users (username, password, role, student_id) VALUES (?, ?, 'advisor', NULL)",
            (username, generate_password_hash(password))
        )
        conn.commit()
        conn.close()

        flash("Advisor registered successfully. Please login.")
        return redirect(url_for("login_advisor"))

    return render_template("register_advisor.html")


@app.route("/login/advisor", methods=["GET", "POST"])
def login_advisor():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE role='advisor' AND username=?", (username,))
        advisor = cur.fetchone()
        conn.close()

        if advisor and check_password_hash(advisor["password"], password):
            session["user_id"] = advisor["id"]
            session["role"] = "advisor"
            session["username"] = advisor["username"]
            session.permanent = False
            return redirect(url_for("advisor_dashboard"))

        flash("Invalid username or password.")
        return redirect(url_for("login_advisor"))

    return render_template("login_advisor.html")


@app.route("/dashboard/advisor")
@login_required(role="advisor")
def advisor_dashboard():
    conn = get_db_connection()
    cur = conn.cursor()

    # Only those that parent approved and are waiting for advisor
    cur.execute("""
        SELECT * FROM leave_requests
        WHERE parent_approved=1
          AND advisor_approved=0
          AND status='Pending Advisor Approval'
        ORDER BY created_at DESC
    """)
    pending_leaves = cur.fetchall()

    cur.execute("""
        SELECT * FROM leave_requests
        WHERE advisor_approved=1
           OR status='Rejected by Advisor'
        ORDER BY created_at DESC
    """)
    processed_leaves = cur.fetchall()

    conn.close()

    return render_template(
        "advisor_dashboard.html",
        pending_leaves=pending_leaves,
        processed_leaves=processed_leaves
    )


@app.route("/advisor/approve/<int:leave_id>", methods=["POST"])
@login_required(role="advisor")
def advisor_approve(leave_id):
    action = request.form.get("action")

    conn = get_db_connection()
    cur = conn.cursor()

    # Only pending-for-advisor leaves should be processed
    cur.execute("""
        SELECT * FROM leave_requests
        WHERE id=? AND parent_approved=1
          AND advisor_approved=0
          AND status='Pending Advisor Approval'
    """, (leave_id,))
    leave = cur.fetchone()

    if not leave:
        flash("Leave not found or already processed.")
        conn.close()
        return redirect(url_for("advisor_dashboard"))

    if action == "approve":
        cur.execute("""
            UPDATE leave_requests
            SET advisor_approved=1,
                status='Pending Warden Approval'
            WHERE id=?
        """, (leave_id,))
        flash("Leave approved and sent to warden.")
    else:
        cur.execute("""
            UPDATE leave_requests
            SET advisor_approved=0,
                status='Rejected by Advisor'
            WHERE id=?
        """, (leave_id,))
        flash("Leave rejected by advisor.")

    conn.commit()
    conn.close()
    return redirect(url_for("advisor_dashboard"))


# =================== WARDEN AUTH & DASHBOARD ===================

@app.route("/register/warden", methods=["GET", "POST"])
def register_warden():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            flash("All fields are required.")
            return redirect(url_for("register_warden"))

        # ✅ Password length restriction
        if len(password) < 6 or len(password) > 12:
            flash("Password must be 6–12 characters long.")
            return redirect(url_for("register_warden"))

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("SELECT * FROM users WHERE role='warden' AND username=?", (username,))
        existing = cur.fetchone()
        if existing:
            flash("Warden username already exists.")
            conn.close()
            return redirect(url_for("register_warden"))

        cur.execute(
            "INSERT INTO users (username, password, role, student_id) VALUES (?, ?, 'warden', NULL)",
            (username, generate_password_hash(password))
        )
        conn.commit()
        conn.close()

        flash("Warden registered successfully. Please login.")
        return redirect(url_for("login_warden"))

    return render_template("register_warden.html")


@app.route("/login/warden", methods=["GET", "POST"])
def login_warden():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE role='warden' AND username=?", (username,))
        warden = cur.fetchone()
        conn.close()

        if warden and check_password_hash(warden["password"], password):
            session["user_id"] = warden["id"]
            session["role"] = "warden"
            session["username"] = warden["username"]
            session.permanent = False
            return redirect(url_for("warden_dashboard"))

        flash("Invalid username or password.")
        return redirect(url_for("login_warden"))

    return render_template("login_warden.html")


@app.route("/dashboard/warden")
@login_required(role="warden")
def warden_dashboard():
    conn = get_db_connection()
    cur = conn.cursor()

    # Only those that parent + advisor approved and are waiting for warden
    cur.execute("""
        SELECT * FROM leave_requests
        WHERE parent_approved=1
          AND advisor_approved=1
          AND warden_approved=0
          AND status='Pending Warden Approval'
        ORDER BY created_at DESC
    """)
    pending_leaves = cur.fetchall()

    cur.execute("""
        SELECT * FROM leave_requests
        WHERE warden_approved=1
           OR status='Rejected by Warden'
        ORDER BY created_at DESC
    """)
    processed_leaves = cur.fetchall()

    conn.close()

    return render_template(
        "warden_dashboard.html",
        pending_leaves=pending_leaves,
        processed_leaves=processed_leaves
    )


@app.route("/warden/approve/<int:leave_id>", methods=["POST"])
@login_required(role="warden")
def warden_approve(leave_id):
    action = request.form.get("action")

    conn = get_db_connection()
    cur = conn.cursor()

    # Only pending-for-warden leaves should be processed
    cur.execute("""
        SELECT * FROM leave_requests
        WHERE id=? AND parent_approved=1
          AND advisor_approved=1
          AND warden_approved=0
          AND status='Pending Warden Approval'
    """, (leave_id,))
    leave = cur.fetchone()

    if not leave:
        flash("Leave not found or already processed.")
        conn.close()
        return redirect(url_for("warden_dashboard"))

    if action == "approve":
        cur.execute("""
            UPDATE leave_requests
            SET warden_approved=1,
                status='Approved'
            WHERE id=?
        """, (leave_id,))
        flash("Leave finally approved by warden.")
    else:
        cur.execute("""
            UPDATE leave_requests
            SET warden_approved=0,
                status='Rejected by Warden'
            WHERE id=?
        """, (leave_id,))
        flash("Leave rejected by warden.")

    conn.commit()
    conn.close()
    return redirect(url_for("warden_dashboard"))


# =================== ADMIN AUTH & DASHBOARD ===================

@app.route("/login/admin", methods=["GET", "POST"])
def login_admin():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE role='admin' AND username=?", (username,))
        admin = cur.fetchone()
        conn.close()

        if admin and check_password_hash(admin["password"], password):
            session["user_id"] = admin["id"]
            session["role"] = "admin"
            session["username"] = admin["username"]
            session.permanent = False
            return redirect(url_for("admin_dashboard"))

        flash("Invalid admin credentials.")
        return redirect(url_for("login_admin"))

    return render_template("login_admin.html")


@app.route("/dashboard/admin")
@login_required(role="admin")
def admin_dashboard():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT * FROM users ORDER BY role, username")
    users = cur.fetchall()

    cur.execute("SELECT * FROM leave_requests ORDER BY created_at DESC")
    leaves = cur.fetchall()

    conn.close()

    return render_template("admin_dashboard.html", users=users, leaves=leaves)


# =================== LOGOUT ===================

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.")
    return redirect(url_for("index"))


# =================== RUN APP ===================

if __name__ == "__main__":
    app.run(debug =True)
