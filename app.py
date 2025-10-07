# app.py
from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import Markup, escape

# ✅ Flask App Initialization
app = Flask(__name__)
app.secret_key = 'change_this_secret_to_something_secure'

# ✅ Define your template filter AFTER app is created
@app.template_filter('nl2br')
def nl2br(value):
    return Markup('<br>'.join(escape(value).split('\n')))

DB = 'database.db'
SITE_NAME = "TaskZen"
MIN_WITHDRAW = 50  # minimum points required to request withdraw


DB = 'database.db'
SITE_NAME = "TaskZen"
MIN_WITHDRAW = 50  # minimum points required to request withdraw

# -----------------------------
# DB helpers
# -----------------------------
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    
    # Check if columns exist, if not, add them
def add_missing_columns():
    conn = get_db()
    c = conn.cursor()
    # Add agent_request column if missing
    try:
        c.execute("ALTER TABLE users ADD COLUMN agent_request INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass  # column already exists

    # Add partnership_request column if missing
    try:
        c.execute("ALTER TABLE users ADD COLUMN partnership_request INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass  # column already exists

    conn.commit()
    conn.close()


    # users (approved flag for admin approval)
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password TEXT,
                    balance INTEGER DEFAULT 0,
                    approved INTEGER DEFAULT 0,
                    lang TEXT DEFAULT 'en'
                )''')
    # users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    balance INTEGER DEFAULT 0,
    approved INTEGER DEFAULT 0,
    agent_request INTEGER DEFAULT 0,
    partnership_request INTEGER DEFAULT 0,
    profile_pic TEXT,
    lang TEXT DEFAULT 'en'
                )''')


    # tasks
    c.execute('''CREATE TABLE IF NOT EXISTS tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT,
                    description TEXT,
                    reward INTEGER,
                    type TEXT DEFAULT 'generic',
                    active INTEGER DEFAULT 1
                )''')

    # completed tasks
    c.execute('''CREATE TABLE IF NOT EXISTS completed_tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    task_id INTEGER,
                    completed_at TEXT DEFAULT CURRENT_TIMESTAMP
                )''')

    # messages
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    email TEXT,
                    message TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )''')

    # withdraw requests
    c.execute('''CREATE TABLE IF NOT EXISTS withdraws (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    amount INTEGER,
                    details TEXT,
                    status TEXT DEFAULT 'pending',
                    requested_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    processed_at TEXT
                )''')

    # admins
    c.execute('''CREATE TABLE IF NOT EXISTS admins (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password TEXT
                )''')

    # create default admin if not exists (password hashed)
    c.execute("SELECT COUNT(*) as cnt FROM admins")
    if c.fetchone()['cnt'] == 0:
        hashed = generate_password_hash("admin123")
        c.execute("INSERT INTO admins (username, password) VALUES (?, ?)", ("admin", hashed))

    # sample tasks
    c.execute("SELECT COUNT(*) as cnt FROM tasks")
    if c.fetchone()['cnt'] == 0:
        sample_tasks = [
            ("Watch a YouTube video", "Type: youtube\nWatch the sponsor video for at least 2 minutes and paste the video URL as proof.", 10, "youtube"),
            ("Visit a link", "Type: visit\nOpen the provided link and keep it open for at least 30 seconds.", 8, "visit"),
            ("Fill a form", "Type: form\nComplete the short form and paste confirmation text as proof.", 12, "form")
        ]
        c.executemany("INSERT INTO tasks (title, description, reward, type) VALUES (?, ?, ?, ?)", sample_tasks)

    conn.commit()
    conn.close()

# -----------------------------
# decorators
# -----------------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'admin' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated

# inject site name to templates
@app.context_processor
def inject_site_name():
    return dict(SITE_NAME=SITE_NAME)

# -----------------------------
# Public routes
# -----------------------------
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        lang = request.form.get('lang','en')
        if not username or not password:
            flash("Provide username and password")
            return redirect(url_for('register'))
        conn = get_db()
        c = conn.cursor()
        try:
            hashed = generate_password_hash(password)
            c.execute("INSERT INTO users (username, password, lang, approved) VALUES (?, ?, ?, 0)", (username, hashed, lang))
            conn.commit()
            flash("Registered. Wait for admin approval.")
        except sqlite3.IntegrityError:
            flash("Username already exists.")
        finally:
            conn.close()
        return redirect(url_for('home'))
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()
        if user and check_password_hash(user['password'], password):
            if user['approved'] == 0:
                flash("Account pending admin approval.")
                return redirect(url_for('home'))
            session['username'] = user['username']
            session['user_id'] = user['id']
            flash("Logged in.")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials.")
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for('home'))

# Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT COUNT(ct.id) as completed_count, IFNULL(SUM(t.reward),0) as earnings
        FROM completed_tasks ct JOIN tasks t ON ct.task_id = t.id
        WHERE ct.user_id=?
    """, (user_id,))
    data = c.fetchone()
    completed = data['completed_count'] if data else 0
    earnings = data['earnings'] if data else 0
    c.execute("SELECT balance FROM users WHERE id=?", (user_id,))
    balance_row = c.fetchone()
    balance = balance_row['balance'] if balance_row else 0
    conn.close()
    return render_template('dashboard.html', username=session['username'], completed=completed, earnings=earnings, balance=balance)

# Tasks
@app.route('/tasks')
@login_required
def task_list():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM tasks WHERE active=1")
    tasks = c.fetchall()
    conn.close()
    return render_template('task_list.html', tasks=tasks)

@app.route('/task/<int:task_id>', methods=['GET','POST'])
@login_required
def task_page(task_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM tasks WHERE id=?", (task_id,))
    task = c.fetchone()
    user_id = session['user_id']
    c.execute("SELECT * FROM completed_tasks WHERE user_id=? AND task_id=?", (user_id, task_id))
    completed = c.fetchone() is not None

    if request.method == 'POST' and not completed:
        c.execute("INSERT INTO completed_tasks (user_id, task_id) VALUES (?, ?)", (user_id, task_id))
        c.execute("UPDATE users SET balance = balance + (SELECT reward FROM tasks WHERE id=?) WHERE id=?", (task_id, user_id))
        conn.commit()
        conn.close()
        flash("Task completed. Points added to your balance.")
        return redirect(url_for('task_page', task_id=task_id))

    conn.close()
    return render_template('task_page.html', task=task, completed=completed)

# Contact
@app.route('/contact', methods=['GET','POST'])
@login_required
def contact():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        message = request.form['message']
        conn = get_db()
        c = conn.cursor()
        c.execute("INSERT INTO messages (username, email, message) VALUES (?, ?, ?)", (username, email, message))
        conn.commit()
        conn.close()
        flash("Message saved. Admin will review it.")
        return redirect(url_for('dashboard'))
    return render_template('contact.html')

#Profile
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user_id = session['user_id']
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user = c.fetchone()

    if request.method == 'POST':
        profile_url = request.form.get('profile_url')
        if profile_url:
            c.execute("UPDATE users SET profile_pic=? WHERE id=?", (profile_url, user_id))
            conn.commit()
            flash("Profile picture updated.")
            return redirect(url_for('profile'))

    conn.close()
    return render_template('profile.html', user=user)


# Withdraw
@app.route('/withdraw', methods=['GET','POST'])
@login_required
def withdraw():
    user_id = session['user_id']
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT balance FROM users WHERE id=?", (user_id,))
    balance_row = c.fetchone()
    balance = balance_row['balance'] if balance_row else 0

    if balance < MIN_WITHDRAW:
        flash(f"You need at least {MIN_WITHDRAW} points to request a withdraw.")
        conn.close()
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        try:
            amount = int(request.form['amount'])
        except:
            flash("Enter a valid integer amount.")
            conn.close()
            return redirect(url_for('withdraw'))

        details = request.form.get('details','')
        if amount <= 0:
            flash("Amount must be positive.")
        elif amount > balance:
            flash("Insufficient balance.")
        elif amount < MIN_WITHDRAW:
            flash(f"Minimum withdraw amount is {MIN_WITHDRAW} points.")
        else:
            c.execute("INSERT INTO withdraws (user_id, amount, details) VALUES (?, ?, ?)", (user_id, amount, details))
            # reserve funds by deducting now
            c.execute("UPDATE users SET balance = balance - ? WHERE id=?", (amount, user_id))
            conn.commit()
            flash("Withdraw request submitted.")

    conn.close()
    return render_template('withdraw.html', balance=balance, min_withdraw=MIN_WITHDRAW)

# -----------------------------
# Admin routes
# -----------------------------
@app.route('/admin/login', methods=['GET','POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM admins WHERE username=?", (username,))
        admin = c.fetchone()
        conn.close()
        if admin and check_password_hash(admin['password'], password):
            session['admin'] = admin['username']
            flash("Admin logged in.")
            return redirect(url_for('admin_dashboard'))
        else:
            flash("Invalid admin credentials.")
            return redirect(url_for('admin_login'))
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    flash("Admin logged out.")
    return redirect(url_for('home'))

@app.route('/admin')
@admin_required
def admin_dashboard():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) as users_count FROM users")
    users_count = c.fetchone()['users_count']
    c.execute("SELECT COUNT(*) as tasks_count FROM tasks")
    tasks_count = c.fetchone()['tasks_count']
    c.execute("SELECT COUNT(*) as pending_withdraws FROM withdraws WHERE status='pending'")
    pending_withdraws = c.fetchone()['pending_withdraws']
    conn.close()
    return render_template('admin_dashboard.html', users_count=users_count, tasks_count=tasks_count, pending_withdraws=pending_withdraws)

# admin - manage users (approve/decline/list)
@app.route('/admin/users')
@admin_required
def admin_users():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users ORDER BY id DESC")
    users = c.fetchall()
    conn.close()
    return render_template('admin_users.html', users=users)

@app.route('/admin/users/approve/<int:uid>')
@admin_required
def admin_user_approve(uid):
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE users SET approved=1 WHERE id=?", (uid,))
    conn.commit()
    conn.close()
    flash("User approved.")
    return redirect(url_for('admin_users'))

@app.route('/admin/users/decline/<int:uid>')
@admin_required
def admin_user_decline(uid):
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE id=?", (uid,))
    conn.commit()
    conn.close()
    flash("User declined and removed.")
    return redirect(url_for('admin_users'))

# Approve partnership request
@app.route('/admin/users/partnership/approve/<int:uid>')
@admin_required
def admin_partnership_approve(uid):
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE users SET partnership_request=1 WHERE id=?", (uid,))
    conn.commit()
    conn.close()
    flash("Partnership approved.")
    return redirect(url_for('admin_users'))

# Approve agent request
@app.route('/admin/users/agent/approve/<int:uid>')
@admin_required
def admin_agent_approve(uid):
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE users SET agent_request=1 WHERE id=?", (uid,))
    conn.commit()
    conn.close()
    flash("Agent approved.")
    return redirect(url_for('admin_users'))


# admin - tasks management
@app.route('/admin/tasks', methods=['GET','POST'])
@admin_required
def admin_tasks():
    conn = get_db()
    c = conn.cursor()
    if request.method == 'POST':
        title = request.form['title']
        desc = request.form['description']
        reward = int(request.form['reward'])
        ttype = request.form.get('type','generic')
        c.execute("INSERT INTO tasks (title, description, reward, type) VALUES (?, ?, ?, ?)", (title, desc, reward, ttype))
        conn.commit()
        flash("Task added.")
    c.execute("SELECT * FROM tasks")
    tasks = c.fetchall()
    conn.close()
    return render_template('admin_tasks.html', tasks=tasks)

@app.route('/admin/tasks/edit/<int:task_id>', methods=['GET','POST'])
@admin_required
def admin_task_edit(task_id):
    conn = get_db()
    c = conn.cursor()
    if request.method == 'POST':
        title = request.form['title']
        desc = request.form['description']
        reward = int(request.form['reward'])
        active = 1 if request.form.get('active') == 'on' else 0
        c.execute("UPDATE tasks SET title=?, description=?, reward=?, active=? WHERE id=?", (title, desc, reward, active, task_id))
        conn.commit()
        conn.close()
        flash("Task updated.")
        return redirect(url_for('admin_tasks'))
    c.execute("SELECT * FROM tasks WHERE id=?", (task_id,))
    task = c.fetchone()
    conn.close()
    return render_template('admin_tasks.html', edit_task=task, tasks=[])

@app.route('/admin/tasks/delete/<int:task_id>')
@admin_required
def admin_task_delete(task_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM tasks WHERE id=?", (task_id,))
    conn.commit()
    conn.close()
    flash("Task deleted.")
    return redirect(url_for('admin_tasks'))

# admin - messages
@app.route('/admin/messages')
@admin_required
def admin_messages():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM messages ORDER BY created_at DESC")
    messages = c.fetchall()
    conn.close()
    return render_template('admin_messages.html', messages=messages)

# admin - withdraws
@app.route('/admin/withdraws')
@admin_required
def admin_withdraws():
    conn = get_db()
    c = conn.cursor()
    c.execute("""SELECT w.*, u.username FROM withdraws w
                 LEFT JOIN users u ON w.user_id = u.id
                 ORDER BY w.requested_at DESC""")
    withdraws = c.fetchall()
    conn.close()
    return render_template('admin_withdraws.html', withdraws=withdraws)

@app.route('/admin/withdraws/approve/<int:wid>')
@admin_required
def admin_withdraw_approve(wid):
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE withdraws SET status='approved', processed_at=CURRENT_TIMESTAMP WHERE id=?", (wid,))
    conn.commit()
    conn.close()
    flash("Withdraw approved.")
    return redirect(url_for('admin_withdraws'))

@app.route('/admin/withdraws/decline/<int:wid>')
@admin_required
def admin_withdraw_decline(wid):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT user_id, amount, status FROM withdraws WHERE id=?", (wid,))
    row = c.fetchone()
    if row and row['status'] == 'pending':
        # refund amount
        c.execute("UPDATE users SET balance = balance + ? WHERE id=?", (row['amount'], row['user_id']))
        c.execute("UPDATE withdraws SET status='declined', processed_at=CURRENT_TIMESTAMP WHERE id=?", (wid,))
        conn.commit()
    conn.close()
    flash("Withdraw declined and amount refunded.")
    return redirect(url_for('admin_withdraws'))

# run
if __name__ == '__main__':
    init_db()
    app.run(debug=True)
