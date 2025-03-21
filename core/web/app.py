from flask import Flask, render_template, jsonify, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
from core.db.database import Database
from core.integration.reconftw_wrapper import ReconFTWWrapper
from core.integration.reconftw_config import ReconFTWConfig

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'dev-key-change-this')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'RECONBUDDY_DB_URL', 
    'postgresql://postgres:postgres@localhost:5432/reconbuddy'
)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    api_key = db.Column(db.String(64), unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

@app.route('/')
@login_required
def dashboard():
    recondb = Database()
    recent_scans = recondb.get_recent_scans(limit=10)
    return render_template('dashboard.html', scans=recent_scans)

@app.route('/scan/<int:scan_id>')
@login_required
def scan_details(scan_id):
    recondb = Database()
    scan = recondb.get_scan(scan_id)
    findings = recondb.get_findings(scan_id)
    return render_template('scan_details.html', scan=scan, findings=findings)

@app.route('/new_scan', methods=['GET', 'POST'])
@login_required
def new_scan():
    if request.method == 'POST':
        domain = request.form.get('domain')
        scan_type = request.form.get('scan_type')
        
        reconftw = ReconFTWWrapper()
        config = ReconFTWConfig()
        
        # Start scan in background
        # TODO: Implement background task queue
        try:
            results = reconftw.run_scan(domain, scan_type)
            return redirect(url_for('dashboard'))
        except Exception as e:
            return render_template('new_scan.html', error=str(e))
            
    return render_template('new_scan.html')

@app.route('/api/scan_status/<int:scan_id>')
@login_required
def scan_status(scan_id):
    recondb = Database()
    scan = recondb.get_scan(scan_id)
    return jsonify({
        'status': scan.status,
        'progress': scan.progress,
        'findings_count': len(scan.findings)
    })

@app.route('/settings')
@login_required
def settings():
    config = ReconFTWConfig()
    return render_template('settings.html', config=config.config)

@app.route('/settings/update', methods=['POST'])
@login_required
def update_settings():
    config = ReconFTWConfig()
    updates = request.get_json()
    config.update_config(updates)
    return jsonify({'status': 'success'})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and user.check_password(request.form.get('password')):
            login_user(user)
            return redirect(url_for('dashboard'))
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/api/findings/<int:scan_id>')
@login_required
def get_findings(scan_id):
    recondb = Database()
    findings = recondb.get_findings(scan_id)
    return jsonify([{
        'id': f.id,
        'type': f.type,
        'name': f.name,
        'severity': f.severity,
        'description': f.description,
        'metadata': f.metadata
    } for f in findings])

if __name__ == '__main__':
    app.run(debug=True) 