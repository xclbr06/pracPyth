from flask import Flask, render_template, request, session, redirect, flash, url_for
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = 'supersecretkey'

def init_db():
    conn = sqlite3.connect('database.db')
    cursor  = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            course TEXT NOT NULL,
            section TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()
    
init_db()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.after_request
def add_cache_control(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    else:
        return render_template('login.html', hide_nav_footer=True)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        first_name = request.form['first_name'].strip()
        last_name = request.form['last_name'].strip()
        course = request.form['course'].strip()
        section = request.form['section'].strip()
        email = request.form['email'].strip()
        password = request.form['password']

        if not all([first_name, last_name, course, section, email, password]):
            flash('All fields are required!', 'first_name')
            return render_template('register.html', hide_nav_footer=True)

        if '@' not in email or '.' not in email:
            flash('Invalid email format!', 'email')
            return render_template('register.html', hide_nav_footer=True)

        hashed_password = generate_password_hash(password)

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO users (first_name, last_name, course, section, email, password)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (first_name, last_name, course, section, email, hashed_password))
            conn.commit()
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already exists!', 'email')
        finally:
            conn.close()

    return render_template('register.html', hide_nav_footer=True)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password']

        if not email:
            flash('Email is required!','email' )
            return render_template('login.html', hide_nav_footer=True)
        
        if not password:
            flash('Password is required!','password' )
            return render_template('login.html', hide_nav_footer=True)

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[6], password):
            session['user_id'] = user[0]
            session['full_name'] = f"{user[1]} {user[2]}"
            session['course'] = user[3]
            session['section'] = user[4]
            session['email'] = user[5]
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password!', 'email')

    return render_template('login.html', hide_nav_footer=True)

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    return render_template('dashboard.html', user=user)

@app.route('/index')  
@login_required
def index():
    return render_template('index.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.route('/about')  
@login_required
def about():
    return render_template('about.html')

@app.route('/hobbies')  
@login_required
def hobbies():
    return render_template('hobbies.html')

@app.route('/profession')  
@login_required
def profession():
    return render_template('profession.html')

@app.route('/food')  
@login_required
def food():
    return render_template('food.html')

@app.route('/milestones')  
@login_required
def milestones():
    return render_template('milestones.html')

if __name__ == '__main__':  
    app.run(debug=True)