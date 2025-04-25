from flask import Flask, render_template, request, redirect, url_for, session, flash,  send_file
from flask_bcrypt import Bcrypt
import MySQLdb
import config


app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure key
bcrypt = Bcrypt(app)

# Database connection
def get_db():
    return MySQLdb.connect(
        host=config.DB_HOST,
        user=config.DB_USER,
        passwd=config.DB_PASSWORD,
        db=config.DB_NAME
    )

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')

        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
                           (name, email, hashed_pw))
            conn.commit()
            flash("Signup successful! Please login.", "success")
            return redirect(url_for('login'))
        except MySQLdb.IntegrityError:
            flash("Email already exists!", "danger")
        finally:
            cursor.close()
            conn.close()
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and bcrypt.check_password_hash(user[3], password):
            session['user_id'] = user[0]
            session['name'] = user[1]
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials", "danger")
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please login to access dashboard", "warning")
        return redirect(url_for('login'))
    return render_template('dashboard.html', name=session['name'])


@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully", "info")
    return redirect(url_for('login')) 



if __name__ == '__main__':
    app.run(debug=True)