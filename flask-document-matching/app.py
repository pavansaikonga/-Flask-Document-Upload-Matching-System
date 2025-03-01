import os
import sqlite3
import datetime
import hashlib
from flask import Flask, request, jsonify, session, g, send_from_directory, render_template, redirect, url_for

# -------------------------------------------
# Configuration and Initialization
# -------------------------------------------
app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change to a strong secret key

DATABASE = 'project.db'
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# -------------------------------------------
# Database Helpers
# -------------------------------------------
# def get_db():
#     db = getattr(g, '_database', None)
#     if db is None:
#         db = g._database = sqlite3.connect(DATABASE)
#         db.row_factory = sqlite3.Row
#     return db

def get_db():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    # Replace this with a secure hashing function (e.g., bcrypt)
    return password  

def create_tables():
    """Create tables if they don't exist and insert a default admin"""
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password_hash TEXT,
                role TEXT DEFAULT 'user',
                credits INTEGER DEFAULT 20,
                last_credit_reset TEXT
            )''')
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                filename TEXT,
                content TEXT,
                created_at TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )''')
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS credit_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                requested_credits INTEGER,
                status TEXT DEFAULT 'pending',
                created_at TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )''')

        # Insert default admin if not exists
        admin_username = 'admin'
        admin_password = hash_password('admin123')  # Change this later!
        cursor.execute("SELECT * FROM users WHERE username = ?", (admin_username,))
        if not cursor.fetchone():
            cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')", 
                           (admin_username, admin_password))
        
        db.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# -------------------------------------------
# Utility Functions
# -------------------------------------------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def check_daily_credit_reset(user):
    """Reset credits to 20 if last reset is missing or not equal to today's date.
       This will NOT override adjustments made by admin if last_credit_reset is set to today.
    """
    today = datetime.date.today().isoformat()
    last_reset = user['last_credit_reset']
    if not last_reset or last_reset.strip() != today:
        db = get_db()
        db.execute('UPDATE users SET credits = ?, last_credit_reset = ? WHERE id = ?', (20, today, user['id']))
        db.commit()
        user = dict(user)
        user['credits'] = 20
        user['last_credit_reset'] = today
    return user

def login_required(f):
    """Decorator to check login status."""
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

def admin_required(f):
    """Decorator to check for admin role."""
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login_page'))
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        if user['role'] != 'admin':
            return jsonify({"error": "Admin privileges required."}), 403
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

def simple_text_similarity(text1, text2):
    """Basic similarity: percentage of common words."""
    words1 = set(text1.lower().split())
    words2 = set(text2.lower().split())
    if not words1 or not words2:
        return 0.0
    common = words1.intersection(words2)
    return len(common) / float(min(len(words1), len(words2)))

# -------------------------------------------
# Frontend Routes to Render HTML Pages
# -------------------------------------------
@app.route('/')
def index():
    # Default landing page is the login page.
    return redirect(url_for('login_page'))

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route("/auth/logout", methods=["POST"])
def logout():
    session.clear()  # Clear session data
    return jsonify({"message": "Logged out successfully"})

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/profile')
@login_required
def profile_page():
    return render_template('profile.html')

@app.route('/upload')
@login_required
def upload_page():
    return render_template('upload.html')

@app.route('/credit_request')
@login_required
def credit_request_page():
    return render_template('request.html')

@app.route('/admin_dashboard')
@login_required
def admin_dashboard_page():
    return render_template('admin.html')

@app.route('/admin_dashboard')
@admin_required
def admin_dashboard():
    db = get_db()
    users = db.execute("SELECT id, username, role FROM users").fetchall()
    requests = db.execute("SELECT * FROM credit_requests WHERE status = 'pending'").fetchall()
    
    return jsonify({
        "users": [dict(user) for user in users],
        "pending_credit_requests": [dict(req) for req in requests]
    })


@app.route('/matches_page')
@login_required
def matches_page():
    # Expecting a query parameter docId in URL, e.g., /matches_page?docId=1
    return render_template('matches.html')

# -------------------------------------------
# API Endpoints
# -------------------------------------------

# User Registration
@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"error": "Username and password are required."}), 400
    username = data['username']
    password_hash = hash_password(data['password'])
    db = get_db()
    try:
        db.execute('INSERT INTO users (username, password_hash, last_credit_reset) VALUES (?, ?, ?)',
                   (username, password_hash, datetime.date.today().isoformat()))
        db.commit()
        return jsonify({"message": "User registered successfully."}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists."}), 409

# User Login (Session-based)
@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"error": "Username and password are required."}), 400

    username = data['username']
    password_hash = hash_password(data['password'])
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username = ? AND password_hash = ?', (username, password_hash)).fetchone()

    if user:
        session['user_id'] = user['id']
        session['role'] = user['role']

        if user['role'] == 'admin':
            return jsonify({"message": "Admin login successful.", "redirect": url_for('admin_dashboard_page')})
        else:
            return jsonify({"message": "User login successful.", "redirect": url_for('profile_page')})
    else:
        return jsonify({"error": "Invalid credentials."}), 401






# Get User Profile & Credits
@app.route('/user/profile', methods=['GET'])
@login_required
def profile():
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    user = check_daily_credit_reset(user)
    # Get user's documents
    docs = db.execute('SELECT id, filename, created_at FROM documents WHERE user_id = ?', (session['user_id'],)).fetchall()
    # Get credit requests
    requests_list = db.execute('SELECT id, requested_credits, status, created_at FROM credit_requests WHERE user_id = ?', (session['user_id'],)).fetchall()
    return jsonify({
        "username": user['username'],
        "role": user['role'],
        "credits": user['credits'],
        "documents": [dict(doc) for doc in docs],
        "credit_requests": [dict(req) for req in requests_list]
    })

# Document Upload & Scan (Deducts 1 Credit)
@app.route('/scanUpload', methods=['POST'])
@login_required
def scan_upload():
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request."}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file."}), 400
    content = file.read().decode('utf-8')  # assuming plain text file
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    user = check_daily_credit_reset(user)
    if user['credits'] <= 0:
        return jsonify({"error": "Insufficient credits. Please request additional credits or wait for reset."}), 402
    # Save file to uploads folder
    filename = f"{session['user_id']}{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}{file.filename}"
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    # Insert document record into database
    created_at = datetime.datetime.now().isoformat()
    db.execute('INSERT INTO documents (user_id, filename, content, created_at) VALUES (?, ?, ?, ?)',
               (session['user_id'], filename, content, created_at))
    # Deduct 1 credit
    new_credit = user['credits'] - 1
    db.execute('UPDATE users SET credits = ? WHERE id = ?', (new_credit, session['user_id']))
    db.commit()
    return jsonify({"message": "File uploaded and scanned successfully.", "remaining_credits": new_credit})

# Get Matching Documents Based on Similarity
@app.route('/matches/<int:docId>', methods=['GET'])
@login_required
def get_matches(docId):
    db = get_db()
    doc = db.execute('SELECT * FROM documents WHERE id = ? AND user_id = ?', (docId, session['user_id'])).fetchone()
    if not doc:
        return jsonify({"error": "Document not found."}), 404
    target_text = doc['content']
    docs = db.execute('SELECT * FROM documents WHERE id != ?', (docId,)).fetchall()
    similar_docs = []
    for other in docs:
        score = simple_text_similarity(target_text, other['content'])
        if score >= 0.3:
            similar_docs.append({
                "id": other["id"],
                "filename": other["filename"],
                "similarity": round(score, 2)
            })
    similar_docs.sort(key=lambda x: x["similarity"], reverse=True)
    return jsonify({"matches": similar_docs})

# Request Additional Credits (Submission Endpoint)
@app.route('/credits/request', methods=['POST'])
@login_required
def request_credits():
    requested_credits = request.form.get('requested_credits')
    if not requested_credits or int(requested_credits) <= 0:
        return jsonify({"error": "Invalid requested credits"}), 400
    
    created_at = datetime.datetime.now().isoformat()
    db = get_db()
    db.execute('INSERT INTO credit_requests (user_id, requested_credits, created_at) VALUES (?, ?, ?)',
               (session['user_id'], requested_credits, created_at))
    db.commit()
    
    # After submission, redirect back to profile page.
    return redirect(url_for('profile_page'))

# Admin Analytics Dashboard
@app.route('/admin/analytics', methods=['GET'])
@admin_required
def admin_analytics():
    db = get_db()
    scans = db.execute('SELECT user_id, COUNT(*) as scan_count FROM documents GROUP BY user_id').fetchall()
    scans_list = [dict(row) for row in scans]
    credit_requests = db.execute('SELECT * FROM credit_requests').fetchall()
    credit_requests_list = [dict(row) for row in credit_requests]
    top_users = sorted(scans_list, key=lambda x: x["scan_count"], reverse=True)
    analytics = {
        "scans_per_user": scans_list,
        "credit_requests": credit_requests_list,
        "top_users": top_users
    }
    return jsonify(analytics)
@app.route('/admin/credit_request/<int:req_id>/<action>', methods=['POST'])
@admin_required
def process_credit_request(req_id, action):
    if action not in ["approve", "deny"]:
        return jsonify({"error": "Invalid action"}), 400

    db = get_db()
    request_entry = db.execute("SELECT * FROM credit_requests WHERE id = ?", (req_id,)).fetchone()

    if not request_entry:
        return jsonify({"error": "Credit request not found"}), 404

    if request_entry["status"] != "pending":
        return jsonify({"error": "Request is already processed"}), 400

    if action == "approve":
        db.execute("UPDATE credit_requests SET status = 'approved' WHERE id = ?", (req_id,))
        db.execute("UPDATE users SET credits = credits + ? WHERE id = ?", 
                   (request_entry["requested_credits"], request_entry["user_id"]))
    elif action == "deny":
        db.execute("UPDATE credit_requests SET status = 'denied' WHERE id = ?", (req_id,))

    db.commit()

    # Return updated request status
    return jsonify({
        "message": f"Request {req_id} {action}d successfully",
        "updated_status": action
    })

    
    
    

    # Mock database update logic
    if action == "approve":
        return jsonify({"message": f"Request {req_id} approved successfully"})
    elif action == "deny":
        return jsonify({"message": f"Request {req_id} denied successfully"})




# Admin: Manually Adjust User Credits
@app.route('/admin/adjust_credits', methods=['POST'])
@admin_required
def adjust_credits():
    user_id = request.form.get('user_id')
    adjustment = request.form.get('adjustment')
    if not user_id or not adjustment:
        return jsonify({"error": "User ID and adjustment amount are required."}), 400
    try:
        adjustment = int(adjustment)
    except ValueError:
        return jsonify({"error": "Adjustment must be an integer."}), 400

    today = datetime.date.today().isoformat()
    db = get_db()
    # Update the user's credits and set last_credit_reset to today so daily reset won't override the change.
    db.execute("UPDATE users SET credits = credits + ?, last_credit_reset = ? WHERE id = ?", 
               (adjustment, today, user_id))
    db.commit()
    return jsonify({"message": f"User {user_id} credits adjusted by {adjustment}."})

# Serve uploaded files (for testing/demo purposes)
@app.route('/uploads/<filename>', methods=['GET'])
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

# -------------------------------------------
# Run the Application
# -------------------------------------------
if __name__ == '__main__':
    create_tables()
    app.run(debug=True)