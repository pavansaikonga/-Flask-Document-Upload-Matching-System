📌 Flask Document Upload & Matching System

A Flask-based web application that allows users to register, upload documents, request additional credits, and find matching documents. Admins can manage users and credit requests.

🚀 Features
✅ User Authentication (Login & Registration)
✅ File Upload & Scanning(TXT file) ✅ Profile Page (View & Manage Uploaded Files)
✅ Credit Request System (Request Additional Credits)
✅ Admin Dashboard (Manage Users & Approve Requests)
✅ SQLite Database Integration

📁 Project Structure
/flask-document-matching │── /static │ ├── /css │ │ ├── styles.css │── /templates │ ├── admin.html │ ├── login.html │ ├── matches.html │ ├── profile.html │ ├── register.html │ ├── request.html │ ├── upload.html │── uploads/ # (For storing uploaded files) │── app.py # (Main Flask application) │── database.db # (SQLite Database) │── requirements.txt # (Python dependencies) │── README.md # (Project Documentation)

🛠 Installation
1️⃣ Clone the Repository
sh

git clone https://github.com/pavansaikonga/-Flask-Document-Upload-Matching-System.git

cd flask-document-matching

2️⃣ Create & Activate a Virtual Environment
sh

python -m venv venv

Activate virtual environment
Windows:
venv\Scripts\activate

macOS/Linux:
source venv/bin/activate

3️⃣ Install Dependencies
sh

pip install -r requirements.txt

4️⃣ Initialize Database
sh

python

from app import init_db init_db() exit()

5️⃣ Run the Application
sh

python3 app.py

📌 Open your browser and visit:

http://127.0.0.1:5000

📝 Usage Guide
1️⃣ User Registration & Login
Users can register and log in to their accounts.
After logging in, they are redirected to their profile page.
2️⃣ Upload & Scan Documents
Users can upload .txt file.
Uploaded documents are stored in the /uploads folder.
3️⃣ Request Additional Credits
Users can request additional credits via the request page.
Admins can approve/reject these requests.
4️⃣ Admin Panel
Admins can manage users, view files, and approve/reject credit requests.
🔧 Environment Variables (Optional)
Variable	Description	Default
SECRET_KEY	Flask secret key for session management	'your_secret_key'
UPLOAD_FOLDER	Path to store uploaded files	'uploads'
ALLOWED_EXTENSIONS	Allowed file types for upload	{txt, pdf, doc, docx, xlsx, csv}
🛠 Technology Stack
Flask (Python Web Framework)
SQLite (Lightweight Database)
HTML, CSS, JavaScript (Frontend)
📌 Future Enhancements
🔹 Match Similar Documents using TF-IDF or NLP
🔹 User Credit System (Restrict file uploads based on credits)
🔹 Better UI/UX with Bootstrap

🛡 License
This project is licensed under the MIT License.

🤝 Contributing
Fork the repository
Create a feature branch (git checkout -b new-feature)
Commit your changes (git commit -m "Added new feature")
Push to your branch (git push origin new-feature)
Submit a pull request 🚀
📧 Contact & Support
💡 Have questions or suggestions? Feel free to reach out via GitHub Issues.

📌 Enjoy building with Flask! 🚀
