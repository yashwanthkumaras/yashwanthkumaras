from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
import joblib
import os

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'abccberfdadeffed'

# Load pre-trained model and selected features
model = joblib.load('best_ids_model.pkl')
selected_features = joblib.load('selected_features.pkl')  # This should be a list of feature names

# SQLite database file
DB_FILE = "intrusion.db"

# Create the users table if it doesn't exist
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

# Get DB connection
def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

# Home route
@app.route('/')
def index():
    return render_template('index.html')

# About route
@app.route('/about')
def about():
    return render_template('about.html')

# Contact route
@app.route('/contact')
def contact():
    return render_template('contact.html')

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])

        try:
            db = get_db_connection()
            cursor = db.cursor()
            cursor.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                           (name, email, password))
            db.commit()
            cursor.close()
            db.close()
            flash("✅ Registered successfully. Please log in.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("⚠ Email already registered. Please log in.", "warning")
            return redirect(url_for('register'))
    
    return render_template('register.html')

# Login route
@app.route('/login', methods=['GET', 'POST']) 
def login():
    error_message = None
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session['logged_in'] = True
            session['email'] = email
            return redirect(url_for('prediction'))
        else:
            error_message = "❌ Invalid credentials, please try again!"

    return render_template('login.html', error_message=error_message)

# Prediction route
@app.route('/prediction', methods=['GET', 'POST'])
def prediction():
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        try:
            # Get user input
            user_input = {feature: float(request.form[feature]) for feature in selected_features}
            input_df = pd.DataFrame([user_input])

            # Reorder columns correctly
            input_data = input_df[selected_features]

            # Make prediction
            pred = model.predict(input_data)[0]
            proba = model.predict_proba(input_data)[0]

            result = "Attack 🚨" if pred == 1 else "Normal ✅"
            confidence = f"{max(proba) * 100:.2f}%"

            return render_template('prediction.html', features=selected_features,
                                   result=result, confidence=confidence)
        except Exception as e:
            flash(f"Prediction Error: {str(e)}", "danger")

    return render_template('prediction.html', features=selected_features)

# Logout route
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# Run the app
if __name__ == '__main__':
    init_db()
    print("✅ Database ready")
    print("✅ Flask App Running at http://localhost:5000/")
    app.run(debug=True)
