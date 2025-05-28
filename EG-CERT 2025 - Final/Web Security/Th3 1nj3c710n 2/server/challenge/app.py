import threading
import time
import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['ALLOWED_EXTENSIONS'] = {'svg', 'jpg', 'png', 'bmp'}
app.config['DATABASE_PATH'] = os.path.join('data', 'users.db')




os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('data', exist_ok=True)

def get_flag():
    with open('/tmp/flag_flag_flag.txt') as f:
        return f.read().strip()

def update_flag_periodically():
    while True:
        app.config['FLAG'] = get_flag()
        time.sleep(10)

#app.config['FLAG'] = get_flag()

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

class Data:
    def __init__(self):
        self.msg = "Bio {0}"
    
    def __str__(self):
        return ""


def init_db():
    conn = sqlite3.connect(app.config['DATABASE_PATH'])
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            account_link TEXT,
            profile_picture TEXT,
            bio TEXT,
            is_admin BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username, email, password_hash, account_link=None, profile_picture=None, bio=None, is_admin=False):
        self.id = id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.account_link = account_link
        self.profile_picture = profile_picture
        self.bio = bio
        self.is_admin = is_admin

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect(app.config['DATABASE_PATH'])
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user_data = c.fetchone()
    conn.close()
    
    if user_data:
        return User(
            id=user_data[0],
            username=user_data[1],
            email=user_data[2],
            password_hash=user_data[3],
            account_link=user_data[4],
            profile_picture=user_data[5],
            bio=user_data[6],
            is_admin=bool(user_data[7])
        )
    return None

@app.route('/')
def index():
    
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        bio = "{0}".format(request.form.get('bio'))
        password = request.form.get('password')
        account_link = request.form.get('account_link')
        
        conn = sqlite3.connect(app.config['DATABASE_PATH'])
        c = conn.cursor()
        
        # Check if email already exists
        c.execute('SELECT * FROM users WHERE email = ?', (email,))
        if c.fetchone():
            flash('Email already registered')
            conn.close()
            return redirect(url_for('register'))
        
        # Check if username already exists
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        if c.fetchone():
            flash('Username already taken')
            conn.close()
            return redirect(url_for('register'))
        
        # Handle profile picture upload
        profile_picture = None
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and file.filename:
                if not allowed_file(file.filename):
                    flash('Invalid file type. Allowed types: SVG, JPG, PNG, BMP')
                    conn.close()
                    return redirect(url_for('register'))
                
                filename = secure_filename(f"{uuid.uuid4()}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                profile_picture = filename
        
        # Create new user
        password_hash = generate_password_hash(password)
        c.execute('''
            INSERT INTO users (username, email, password_hash, account_link, profile_picture, bio)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (username, email, password_hash, account_link, profile_picture, bio))
        
        conn.commit()
        conn.close()
        
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    
    if request.method == 'POST':
        identifier = request.form.get('identifier')  # Can be username or email
        password = request.form.get('password')
        
        # VULNERABLE TO SQL INJECTION - Intentionally using string concatenation
        conn = sqlite3.connect(app.config['DATABASE_PATH'])
        c = conn.cursor()
        query = f"SELECT * FROM users WHERE email = '{identifier}' OR username = '{identifier}'"
        c.execute(query)
        user_data = c.fetchone()
        conn.close()
        
        if user_data and check_password_hash(user_data[3], password):
            user = User(
                id="{0}".format(user_data[0]),
                username="{0}".format(user_data[1]),
                email="{0}".format(user_data[2]),
                password_hash="{0}".format(user_data[3]),
                account_link="{0}".format(user_data[4]),
                profile_picture="{0}".format(user_data[5]),
                bio="{0}".format(user_data[6]),
                is_admin=bool(user_data[7])
            )
            login_user(user)
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('user_dashboard'))
        
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('user_dashboard'))
    
    conn = sqlite3.connect(app.config['DATABASE_PATH'])
    c = conn.cursor()
    c.execute('SELECT * FROM users')
    users_data = c.fetchall()
    conn.close()
    
    users = []
    for user_data in users_data:
        users.append(User(
            id=user_data[0],
            username=user_data[1],
            email=user_data[2],
            password_hash=user_data[3],
            account_link=user_data[4],
            profile_picture=user_data[5],
            bio=user_data[6],
            is_admin=bool(user_data[7])
        ))
    
    return render_template('admin_dashboard.html', users=users)

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    message = ("{0}" + current_user.bio).format(Data())
    return render_template('user_dashboard.html', message=message)

@app.route('/user/update', methods=['POST'])
@login_required
def update_user():
    if request.method == 'POST':
        conn = sqlite3.connect(app.config['DATABASE_PATH'])
        c = conn.cursor()
        
        # Update user information
        updates = []
        params = []
        
        if 'username' in request.form:
            updates.append('username = ?')
            params.append(request.form['username'])
        if 'email' in request.form:
            updates.append('email = ?')
            params.append(request.form['email'])
        if 'account_link' in request.form:
            updates.append('account_link = ?')
            params.append(request.form['account_link'])
        if 'bio' in request.form:
            updates.append('bio = ?')
            params.append(request.form['bio'])
        if 'password' in request.form and request.form['password']:
            updates.append('password_hash = ?')
            params.append(generate_password_hash(request.form['password']))
        
        # Handle profile picture update
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and file.filename:
                if not allowed_file(file.filename):
                    flash('Invalid file type. Allowed types: SVG, JPG, PNG, BMP')
                    conn.close()
                    return redirect(url_for('user_dashboard'))
                
                # Delete old profile picture if exists
                c.execute('SELECT profile_picture FROM users WHERE id = ?', (current_user.id,))
                old_picture = c.fetchone()[0]
                if old_picture:
                    old_picture_path = os.path.join(app.config['UPLOAD_FOLDER'], old_picture)
                    if os.path.exists(old_picture_path):
                        os.remove(old_picture_path)
                
                filename = secure_filename(f"{uuid.uuid4()}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                updates.append('profile_picture = ?')
                params.append(filename)
        
        if updates:
            query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
            params.append(current_user.id)
            c.execute(query, params)
            conn.commit()
            flash('Profile updated successfully')
        
        conn.close()
        
    return redirect(url_for('user_dashboard'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('user_dashboard'))
    
    conn = sqlite3.connect(app.config['DATABASE_PATH'])
    c = conn.cursor()
    
    # Get user's profile picture
    c.execute('SELECT profile_picture FROM users WHERE id = ?', (user_id,))
    profile_picture = c.fetchone()[0]
    
    # Delete profile picture if exists
    if profile_picture:
        picture_path = os.path.join(app.config['UPLOAD_FOLDER'], profile_picture)
        if os.path.exists(picture_path):
            os.remove(picture_path)
    
    # Delete user
    c.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    
    flash('User deleted successfully')
    return redirect(url_for('admin_dashboard'))

"""@app.route("/read_file")
def read_file():
    black_list_names = [
        "dev",
        "env",
        "environ",
        "self",
        "proc",
        "werkzeug",
        "site-packages",
        "init",
        "debug",
        "usr",
        "local",
        "lib",
        "home",
        "root",
    ]
    if request.args.get("file") is None:
        response = "Missing Parameter"
    else:
        file_name = request.args.get("file")
        file_name = file_name.replace("./", "")
        for black_list_name in black_list_names:
            if black_list_name in file_name:
                return make_response("Unauthorized Access")
        response = open(file_name).read()

    return make_response(response)"""

@app.route('/health')
def health_check():
    try:
        # Check database connection
        conn = sqlite3.connect(app.config['DATABASE_PATH'])
        conn.close()
        return make_response('OK', 200)
    except Exception as e:
        return make_response('Service Unavailable', 503)

if __name__ == '__main__':
    init_db()
    flag_thread = threading.Thread(target=update_flag_periodically, daemon=True)
    flag_thread.start()
    app.run(host="0.0.0.0", port=8721, debug=True, use_evalex=False) 