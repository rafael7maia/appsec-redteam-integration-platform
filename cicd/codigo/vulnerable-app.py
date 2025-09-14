#!/usr/bin/env python3
"""
Vulnerable Web Application for AppSec Testing
Contains intentional vulnerabilities for demonstration
"""

from flask import Flask, request, render_template_string, redirect, session
import sqlite3
import os
import subprocess
import pickle
import base64

app = Flask(__name__)
app.secret_key = 'weak_secret_key_123'  # Weak crypto

# Hardcoded secrets (GitLeaks will detect these)
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DB_PASSWORD = "super_secret_password_123"
API_KEY = "<STRIPE_API_KEY>"
JWT_SECRET = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

# Initialize database
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT
        )
    ''')
    cursor.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'password123', 'admin@test.com')")
    cursor.execute("INSERT OR IGNORE INTO users VALUES (2, 'user', 'user123', 'user@test.com')")
    # Hardcoded admin credentials
    cursor.execute("INSERT OR IGNORE INTO users VALUES (3, 'root', 'toor123!@#', 'root@company.com')")
    conn.commit()
    conn.close()

@app.route('/')
def home():
    return '''
    <h1>Vulnerable Web App - AppSec Testing</h1>
    <ul>
        <li><a href="/login">Login (SQL Injection)</a></li>
        <li><a href="/search">Search (XSS)</a></li>
        <li><a href="/file">File Access (Path Traversal)</a></li>
        <li><a href="/cmd">Command (Command Injection)</a></li>
        <li><a href="/deserialize">Deserialize (Insecure Deserialization)</a></li>
    </ul>
    '''

# SQL Injection Vulnerability
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # VULNERABLE: SQL Injection
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        
        if user:
            session['user'] = username
            return f"Welcome {username}! User data: {user}"
        else:
            return "Invalid credentials"
    
    return '''
    <form method="post">
        Username: <input name="username" type="text"><br>
        Password: <input name="password" type="password"><br>
        <input type="submit" value="Login">
    </form>
    '''

# XSS Vulnerability
@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        query = request.form['query']
        # VULNERABLE: XSS - No input sanitization
        return f"<h1>Search Results for: {query}</h1><p>No results found.</p>"
    
    return '''
    <form method="post">
        Search: <input name="query" type="text">
        <input type="submit" value="Search">
    </form>
    '''

# Path Traversal Vulnerability
@app.route('/file')
def file_access():
    filename = request.args.get('file', 'default.txt')
    try:
        # VULNERABLE: Path Traversal
        with open(f"files/{filename}", 'r') as f:
            content = f.read()
        return f"<pre>{content}</pre>"
    except:
        return "File not found"

# Command Injection Vulnerability
@app.route('/cmd', methods=['GET', 'POST'])
def command():
    if request.method == 'POST':
        host = request.form['host']
        # VULNERABLE: Command Injection
        result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
        return f"<pre>{result.stdout}</pre>"
    
    return '''
    <form method="post">
        Host to ping: <input name="host" type="text">
        <input type="submit" value="Ping">
    </form>
    '''

# Insecure Deserialization Vulnerability
@app.route('/deserialize', methods=['GET', 'POST'])
def deserialize():
    if request.method == 'POST':
        data = request.form['data']
        try:
            # VULNERABLE: Insecure Deserialization
            decoded = base64.b64decode(data)
            obj = pickle.loads(decoded)
            return f"Deserialized: {obj}"
        except:
            return "Invalid data"
    
    return '''
    <form method="post">
        Base64 Data: <input name="data" type="text">
        <input type="submit" value="Deserialize">
    </form>
    '''

if __name__ == '__main__':
    init_db()
    os.makedirs('files', exist_ok=True)
    with open('files/default.txt', 'w') as f:
        f.write('Default file content')
    with open('files/secret.txt', 'w') as f:
        f.write('SECRET: This should not be accessible!')
    
    app.run(host='0.0.0.0', port=5000, debug=True)