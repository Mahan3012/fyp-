from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json, os, requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.secret_key = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scanner.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    email = db.Column(db.String(120))
    password = db.Column(db.String(80))

class ScanRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(500))
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    total_findings = db.Column(db.Integer)
    scan_duration = db.Column(db.Float)
    findings_json = db.Column(db.Text)

with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', email='admin@example.com', password='admin123')
        db.session.add(admin)
        db.session.commit()

def scan_target(target):
    findings = []
    start = datetime.now()
    try:
        r = requests.get(target, timeout=15, verify=False)
        headers = {
            'Strict-Transport-Security': 'High',
            'Content-Security-Policy': 'High',
            'X-Frame-Options': 'Medium'
        }
        for h, sev in headers.items():
            if h not in r.headers:
                findings.append({
                    'title': f'Missing: {h}',
                    'severity': sev,
                    'category': 'Security Headers',
                    'cvss_score': 8.1 if sev == 'High' else 5.4,
                    'remediation': f'Add {h} header'
                })
    except Exception as e:
        findings.append({'title': f'Error: {str(e)[:50]}', 'severity': 'Info', 'category': 'Network', 'cvss_score': 0, 'remediation': ''})
    end = datetime.now()
    return findings, (end-start).total_seconds()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username'], password=request.form['password']).first()
        if user:
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect('/dashboard')
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user = User(username=request.form['username'], email=request.form['email'], password=request.form['password'])
        db.session.add(user)
        db.session.commit()
        return redirect('/login')
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    user = User.query.get(session['user_id'])
    scans = ScanRecord.query.order_by(ScanRecord.scan_date.desc()).limit(10).all()
    total_scans = ScanRecord.query.count()
    return render_template('dashboard.html', user=user, recent_scans=scans, total_scans=total_scans, total_findings=0, severity_counts={})

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    if 'user_id' not in session:
        return redirect('/login')
    if request.method == 'POST':
        target = request.form['target_url']
        findings, duration = scan_target(target)
        record = ScanRecord(target_url=target, total_findings=len(findings), scan_duration=duration, findings_json=json.dumps(findings))
        db.session.add(record)
        db.session.commit()
        return redirect(f'/scan/{record.id}')
    return render_template('scan.html')

@app.route('/scan/<int:scan_id>')
def scan_results(scan_id):
    if 'user_id' not in session:
        return redirect('/login')
    scan = ScanRecord.query.get(scan_id)
    findings = json.loads(scan.findings_json)
    return render_template('scan_results.html', scan=scan, findings=findings)

@app.route('/history')
def history():
    if 'user_id' not in session:
        return redirect('/login')
    scans = ScanRecord.query.order_by(ScanRecord.scan_date.desc()).all()
    return render_template('history.html', scans=scans)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True, port=5000)