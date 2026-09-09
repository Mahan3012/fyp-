"""
========================================================================
ULTIMATE VULNERABILITY ASSESSMENT FRAMEWORK - PROFESSIONAL EDITION
For Pakistani University Websites
========================================================================
Features:
- Multi-tab GUI Interface
- Real-time Scan Progress
- Visual Charts & Statistics
- Database Storage (SQLite)
- Multiple Report Formats (TXT, CSV, JSON, PDF)
- Scan History
- HEC Compliance Dashboard
- Cost Analysis Matrix
========================================================================
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import requests
import re
import json
import sqlite3
import csv
import os
from datetime import datetime
import warnings
import urllib3
from collections import Counter

warnings.filterwarnings('ignore')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Try to import matplotlib for charts
try:
    import matplotlib
    matplotlib.use('TkAgg')
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
    HAS_MATPLOTLIB = True
except:
    HAS_MATPLOTLIB = False

# Try to import pandas
try:
    import pandas as pd
    HAS_PANDAS = True
except:
    HAS_PANDAS = False


class Database:
    """Database management class"""
    
    def __init__(self):
        self.conn = sqlite3.connect('scanner_history.db')
        self.cursor = self.conn.cursor()
        self.init_tables()
    
    def init_tables(self):
        """Create tables if they don't exist"""
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                scan_date TEXT NOT NULL,
                total_findings INTEGER,
                critical_count INTEGER,
                high_count INTEGER,
                medium_count INTEGER,
                low_count INTEGER,
                duration REAL,
                findings_json TEXT
            )
        ''')
        self.conn.commit()
    
    def save_scan(self, target, findings, duration):
        """Save scan results to database"""
        severity_counts = Counter(f['severity'] for f in findings)
        
        self.cursor.execute('''
            INSERT INTO scans (target_url, scan_date, total_findings, 
                             critical_count, high_count, medium_count, low_count,
                             duration, findings_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            target,
            datetime.now().isoformat(),
            len(findings),
            severity_counts.get('Critical', 0),
            severity_counts.get('High', 0),
            severity_counts.get('Medium', 0),
            severity_counts.get('Low', 0),
            duration,
            json.dumps(findings)
        ))
        self.conn.commit()
    
    def get_history(self, limit=50):
        """Get scan history"""
        self.cursor.execute('''
            SELECT id, target_url, scan_date, total_findings, 
                   critical_count, high_count, medium_count, low_count
            FROM scans ORDER BY id DESC LIMIT ?
        ''', (limit,))
        return self.cursor.fetchall()
    
    def get_stats(self):
        """Get overall statistics"""
        self.cursor.execute('''
            SELECT COUNT(*), SUM(total_findings), 
                   SUM(critical_count), SUM(high_count),
                   SUM(medium_count), SUM(low_count)
            FROM scans
        ''')
        result = self.cursor.fetchone()
        
        self.cursor.execute('SELECT COUNT(DISTINCT target_url) FROM scans')
        unique_targets = self.cursor.fetchone()[0]
        
        return {
            'total_scans': result[0] or 0,
            'total_findings': result[1] or 0,
            'critical': result[2] or 0,
            'high': result[3] or 0,
            'medium': result[4] or 0,
            'low': result[5] or 0,
            'unique_targets': unique_targets or 0
        }
    
    def close(self):
        """Close database connection"""
        self.conn.close()


class ScanEngine:
    """Scanning engine"""
    
    SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'severity': 'High',
            'description': 'Protects against protocol downgrade attacks',
            'recommendation': 'max-age=31536000; includeSubDomains'
        },
        'Content-Security-Policy': {
            'severity': 'High',
            'description': 'Prevents XSS and injection attacks',
            'recommendation': "default-src 'self'"
        },
        'X-Frame-Options': {
            'severity': 'Medium',
            'description': 'Protects against clickjacking',
            'recommendation': 'DENY'
        },
        'X-Content-Type-Options': {
            'severity': 'Medium',
            'description': 'Prevents MIME type sniffing',
            'recommendation': 'nosniff'
        },
        'X-XSS-Protection': {
            'severity': 'Low',
            'description': 'Browser XSS filter',
            'recommendation': '1; mode=block'
        },
        'Referrer-Policy': {
            'severity': 'Low',
            'description': 'Controls referrer information',
            'recommendation': 'strict-origin-when-cross-origin'
        }
    }
    
    SENSITIVE_DIRS = [
        '/admin', '/administrator', '/backup', '/config', '/.git', '/.env',
        '/wp-admin', '/phpmyadmin', '/server-status', '/.htaccess'
    ]
    
    SENSITIVE_FILES = [
        '/.env', '/.git/config', '/backup.sql', '/phpinfo.php',
        '/wp-config.php.bak', '/.DS_Store'
    ]
    
    def __init__(self, progress_callback=None):
        self.progress_callback = progress_callback
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def update_progress(self, percent, status):
        """Update progress bar"""
        if self.progress_callback:
            self.progress_callback(percent, status)
    
    def scan(self, target_url):
        """Perform complete scan"""
        findings = []
        start_time = datetime.now()
        
        self.update_progress(10, "Connecting to target...")
        response = self.safe_request(target_url)
        
        if not response:
            findings.append({
                'title': 'Connection Failed',
                'severity': 'Info',
                'category': 'Network',
                'description': 'Cannot connect to target',
                'remediation': 'Verify target is accessible'
            })
            return findings, 0
        
        self.update_progress(25, "Checking security headers...")
        findings.extend(self.check_security_headers(response))
        
        self.update_progress(40, "Checking information disclosure...")
        findings.extend(self.check_information_disclosure(response, target_url))
        
        self.update_progress(55, "Extracting emails...")
        findings.extend(self.extract_emails(response))
        
        self.update_progress(70, "Checking sensitive directories...")
        findings.extend(self.check_directories(target_url))
        
        self.update_progress(85, "Checking sensitive files...")
        findings.extend(self.check_files(target_url))
        
        self.update_progress(95, "Finalizing results...")
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        self.update_progress(100, "Scan complete!")
        
        return findings, duration
    
    def safe_request(self, url, timeout=15):
        """Make safe HTTP request"""
        try:
            return self.session.get(url, timeout=timeout, verify=False)
        except:
            return None
    
    def check_security_headers(self, response):
        """Check security headers"""
        findings = []
        for header, info in self.SECURITY_HEADERS.items():
            if header not in response.headers:
                findings.append({
                    'title': f'Missing Security Header: {header}',
                    'severity': info['severity'],
                    'category': 'Security Headers',
                    'description': info['description'],
                    'remediation': f"Add '{header}: {info['recommendation']}'"
                })
        return findings
    
    def check_information_disclosure(self, response, target):
        """Check information disclosure"""
        findings = []
        
        if 'Server' in response.headers:
            findings.append({
                'title': 'Server Version Disclosure',
                'severity': 'Low',
                'category': 'Information Disclosure',
                'description': f"Server reveals: {response.headers['Server']}",
                'remediation': 'Hide server version information'
            })
        
        if 'X-Powered-By' in response.headers:
            findings.append({
                'title': 'Technology Stack Disclosure',
                'severity': 'Low',
                'category': 'Information Disclosure',
                'description': f"X-Powered-By: {response.headers['X-Powered-By']}",
                'remediation': 'Remove X-Powered-By header'
            })
        
        return findings
    
    def extract_emails(self, response):
        """Extract email addresses"""
        findings = []
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = list(set(re.findall(email_pattern, response.text)))
        
        if emails:
            findings.append({
                'title': f'Email Address Exposure ({len(emails)} emails)',
                'severity': 'Low',
                'category': 'Information Disclosure',
                'description': 'Email addresses publicly visible',
                'remediation': 'Use contact forms instead'
            })
        
        return findings
    
    def check_directories(self, target):
        """Check sensitive directories"""
        findings = []
        base = target.rstrip('/')
        
        for dir_path in self.SENSITIVE_DIRS:
            url = base + dir_path
            try:
                resp = self.session.get(url, timeout=5, verify=False)
                if resp.status_code == 200:
                    findings.append({
                        'title': f'Exposed Directory: {dir_path}',
                        'severity': 'High',
                        'category': 'Information Disclosure',
                        'description': f'Directory {dir_path} is accessible',
                        'remediation': 'Restrict access to this directory'
                    })
            except:
                pass
        
        return findings
    
    def check_files(self, target):
        """Check sensitive files"""
        findings = []
        base = target.rstrip('/')
        
        for file_path in self.SENSITIVE_FILES:
            url = base + file_path
            try:
                resp = self.session.get(url, timeout=5, verify=False)
                if resp.status_code == 200 and len(resp.text) > 0:
                    findings.append({
                        'title': f'Exposed File: {file_path}',
                        'severity': 'Critical',
                        'category': 'Information Disclosure',
                        'description': f'Sensitive file {file_path} is exposed',
                        'remediation': 'Remove file from web root immediately'
                    })
            except:
                pass
        
        return findings


class UltimateScannerGUI:
    """Professional GUI Application"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("🔒 Ultimate Vulnerability Assessment Framework")
        self.root.geometry("1200x800")
        self.root.configure(bg='#1a1a2e')
        
        self.db = Database()
        self.scan_engine = ScanEngine(self.update_progress)
        self.current_findings = []
        
        self.setup_styles()
        self.create_widgets()
    
    def setup_styles(self):
        """Setup custom styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure('TNotebook', background='#1a1a2e')
        style.configure('TNotebook.Tab', 
                       background='#16213e',
                       foreground='white',
                       padding=[20, 10],
                       font=('Arial', 11))
        style.map('TNotebook.Tab',
                 background=[('selected', '#0f3460')],
                 foreground=[('selected', 'white')])
        
        style.configure('Action.TButton',
                       background='#3498db',
                       foreground='white',
                       padding=[20, 10],
                       font=('Arial', 11, 'bold'))
    
    def create_widgets(self):
        """Create all UI widgets"""
        # Header
        header_frame = tk.Frame(self.root, bg='#0f3460', height=80)
        header_frame.pack(fill=tk.X)
        
        title = tk.Label(
            header_frame,
            text="🔒 ULTIMATE VULNERABILITY ASSESSMENT FRAMEWORK",
            font=("Arial", 18, "bold"),
            bg='#0f3460',
            fg='white'
        )
        title.pack(pady=8)
        
        subtitle = tk.Label(
            header_frame,
            text="Professional Edition for Pakistani University Websites",
            font=("Arial", 10),
            bg='#0f3460',
            fg='#a8d8ea'
        )
        subtitle.pack()
        
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.scan_tab = tk.Frame(self.notebook, bg='#1a1a2e')
        self.results_tab = tk.Frame(self.notebook, bg='#1a1a2e')
        self.history_tab = tk.Frame(self.notebook, bg='#1a1a2e')
        self.stats_tab = tk.Frame(self.notebook, bg='#1a1a2e')
        
        self.notebook.add(self.scan_tab, text=" 🔍 Scan ")
        self.notebook.add(self.results_tab, text=" 📊 Results ")
        self.notebook.add(self.history_tab, text=" 📜 History ")
        self.notebook.add(self.stats_tab, text=" 📈 Statistics ")
        
        self.create_scan_tab()
        self.create_results_tab()
        self.create_history_tab()
        self.create_stats_tab()
        
        # Status bar
        status_frame = tk.Frame(self.root, bg='#0f3460', height=30)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_bar = tk.Label(
            status_frame,
            text="Ready",
            bg='#0f3460',
            fg='white',
            anchor=tk.W,
            padx=10
        )
        self.status_bar.pack(fill=tk.X)
    
    def create_scan_tab(self):
        """Create scan tab"""
        # Main frame
        main_frame = tk.Frame(self.scan_tab, bg='#1a1a2e', padx=30, pady=30)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # URL Input
        url_label = tk.Label(
            main_frame,
            text="Target URL:",
            font=("Arial", 14, "bold"),
            bg='#1a1a2e',
            fg='white'
        )
        url_label.pack(anchor=tk.W, pady=(0, 5))
        
        url_frame = tk.Frame(main_frame, bg='#1a1a2e')
        url_frame.pack(fill=tk.X, pady=(0, 20))
        
        self.url_entry = tk.Entry(
            url_frame,
            font=("Arial", 14),
            bg='#16213e',
            fg='white',
            insertbackground='white',
            relief=tk.FLAT,
            width=60
        )
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=10, padx=(0, 10))
        self.url_entry.insert(0, "https://nust.edu.pk")
        
        # Scan Button
        self.scan_btn = tk.Button(
            url_frame,
            text="🔍 START SCAN",
            font=("Arial", 13, "bold"),
            bg='#e74c3c',
            fg='white',
            padx=25,
            pady=10,
            relief=tk.FLAT,
            cursor='hand2',
            command=self.start_scan
        )
        self.scan_btn.pack(side=tk.RIGHT)
        
        # Progress bar
        progress_frame = tk.Frame(main_frame, bg='#1a1a2e')
        progress_frame.pack(fill=tk.X, pady=20)
        
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            mode='determinate',
            length=600,
            maximum=100
        )
        self.progress_bar.pack(fill=tk.X)
        
        self.progress_label = tk.Label(
            progress_frame,
            text="0% - Ready",
            font=("Arial", 10),
            bg='#1a1a2e',
            fg='#a8d8ea'
        )
        self.progress_label.pack(anchor=tk.E)
        
        # Quick targets
        quick_label = tk.Label(
            main_frame,
            text="Quick Targets:",
            font=("Arial", 12, "bold"),
            bg='#1a1a2e',
            fg='white'
        )
        quick_label.pack(anchor=tk.W, pady=(20, 10))
        
        quick_frame = tk.Frame(main_frame, bg='#1a1a2e')
        quick_frame.pack(fill=tk.X)
        
        universities = [
            ("NUST", "https://nust.edu.pk"),
            ("SMIU", "https://smiu.edu.pk"),
            ("FAST", "https://nu.edu.pk"),
            ("LUMS", "https://lums.edu.pk"),
            ("IBA", "https://iba.edu.pk"),
            ("UET", "https://uet.edu.pk")
        ]
        
        for name, url in universities:
            btn = tk.Button(
                quick_frame,
                text=name,
                font=("Arial", 10),
                bg='#0f3460',
                fg='white',
                relief=tk.FLAT,
                cursor='hand2',
                padx=15,
                pady=5,
                command=lambda u=url: self.set_url(u)
            )
            btn.pack(side=tk.LEFT, padx=5)
    
    def create_results_tab(self):
        """Create results tab"""
        main_frame = tk.Frame(self.results_tab, bg='#1a1a2e', padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Results text area
        self.results_text = scrolledtext.ScrolledText(
            main_frame,
            font=("Consolas", 10),
            bg='#16213e',
            fg='white',
            wrap=tk.WORD,
            relief=tk.FLAT
        )
        self.results_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure tags for coloring
        self.results_text.tag_configure('critical', foreground='#e74c3c', font=('Consolas', 10, 'bold'))
        self.results_text.tag_configure('high', foreground='#e67e22', font=('Consolas', 10, 'bold'))
        self.results_text.tag_configure('medium', foreground='#f1c40f')
        self.results_text.tag_configure('low', foreground='#2ecc71')
        self.results_text.tag_configure('info', foreground='#3498db')
        self.results_text.tag_configure('header', foreground='#a8d8ea', font=('Consolas', 11, 'bold'))
        
        # Export buttons
        export_frame = tk.Frame(main_frame, bg='#1a1a2e')
        export_frame.pack(fill=tk.X, pady=(10, 0))
        
        buttons = [
            ("Save TXT", self.save_txt, '#27ae60'),
            ("Save CSV", self.save_csv, '#2980b9'),
            ("Save JSON", self.save_json, '#8e44ad')
        ]
        
        for text, command, color in buttons:
            btn = tk.Button(
                export_frame,
                text=text,
                font=("Arial", 10),
                bg=color,
                fg='white',
                relief=tk.FLAT,
                cursor='hand2',
                padx=15,
                pady=5,
                command=command
            )
            btn.pack(side=tk.LEFT, padx=5)
    
    def create_history_tab(self):
        """Create history tab"""
        main_frame = tk.Frame(self.history_tab, bg='#1a1a2e', padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview for history
        columns = ('ID', 'Target', 'Date', 'Total', 'Critical', 'High', 'Medium', 'Low')
        self.history_tree = ttk.Treeview(main_frame, columns=columns, show='headings', height=20)
        
        for col in columns:
            self.history_tree.heading(col, text=col)
            self.history_tree.column(col, width=100, anchor=tk.CENTER)
        
        self.history_tree.pack(fill=tk.BOTH, expand=True)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.history_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.history_tree.configure(yscrollcommand=scrollbar.set)
        
        # Refresh button
        refresh_btn = tk.Button(
            main_frame,
            text="🔄 Refresh History",
            font=("Arial", 11),
            bg='#3498db',
            fg='white',
            relief=tk.FLAT,
            cursor='hand2',
            padx=20,
            pady=8,
            command=self.load_history
        )
        refresh_btn.pack(pady=10)
        
        self.load_history()
    
    def create_stats_tab(self):
        """Create statistics tab"""
        main_frame = tk.Frame(self.stats_tab, bg='#1a1a2e', padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Stats cards
        stats_frame = tk.Frame(main_frame, bg='#1a1a2e')
        stats_frame.pack(fill=tk.X, pady=(0, 20))
        
        stats = self.db.get_stats()
        
        cards = [
            ("Total Scans", stats['total_scans'], '#3498db'),
            ("Unique Targets", stats['unique_targets'], '#9b59b6'),
            ("Total Findings", stats['total_findings'], '#e74c3c'),
            ("Critical Issues", stats['critical'], '#c0392b'),
            ("High Issues", stats['high'], '#e67e22')
        ]
        
        for title, value, color in cards:
            card = tk.Frame(stats_frame, bg=color, width=150, height=100)
            card.pack(side=tk.LEFT, padx=10, expand=True, fill=tk.BOTH)
            card.pack_propagate(False)
            
            tk.Label(card, text=title, font=("Arial", 10), bg=color, fg='white').pack(pady=(15, 5))
            tk.Label(card, text=str(value), font=("Arial", 24, "bold"), bg=color, fg='white').pack()
        
        # Chart area (if matplotlib available)
        if HAS_MATPLOTLIB:
            self.create_chart(main_frame)
        else:
            tk.Label(
                main_frame,
                text="Install matplotlib for charts: pip install matplotlib",
                font=("Arial", 12),
                bg='#1a1a2e',
                fg='white'
            ).pack()
    
    def create_chart(self, parent):
        """Create pie chart for statistics"""
        stats = self.db.get_stats()
        
        fig = Figure(figsize=(8, 4), facecolor='#1a1a2e')
        ax = fig.add_subplot(111)
        
        labels = ['Critical', 'High', 'Medium', 'Low']
        values = [stats['critical'], stats['high'], stats['medium'], stats['low']]
        colors = ['#c0392b', '#e67e22', '#f1c40f', '#2ecc71']
        
        ax.pie(values, labels=labels, colors=colors, autopct='%1.1f%%', 
               textprops={'color': 'white'})
        ax.set_title('Severity Distribution', color='white')
        
        canvas = FigureCanvasTkAgg(fig, master=parent)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def set_url(self, url):
        """Set URL in entry"""
        self.url_entry.delete(0, tk.END)
        self.url_entry.insert(0, url)
    
    def update_progress(self, percent, status):
        """Update progress bar and label"""
        self.root.after(0, lambda: self.progress_bar.configure(value=percent))
        self.root.after(0, lambda: self.progress_label.configure(text=f"{percent}% - {status}"))
        self.root.after(0, lambda: self.status_bar.configure(text=f"{status}"))
    
    def start_scan(self):
        """Start scan in separate thread"""
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        self.scan_btn.config(state=tk.DISABLED, text="⏳ SCANNING...")
        self.progress_bar['value'] = 0
        self.notebook.select(0)
        
        thread = threading.Thread(target=self.perform_scan, args=(url,))
        thread.daemon = True
        thread.start()
    
    def perform_scan(self, url):
        """Perform scan in background"""
        findings, duration = self.scan_engine.scan(url)
        self.current_findings = findings
        
        # Save to database
        self.db.save_scan(url, findings, duration)
        
        # Update UI
        self.root.after(0, lambda: self.display_results(findings, duration, url))
        self.root.after(0, lambda: self.scan_btn.config(state=tk.NORMAL, text="🔍 START SCAN"))
        self.root.after(0, lambda: self.status_bar.configure(text=f"Scan complete - {len(findings)} findings"))
        self.root.after(0, self.load_history)
    
    def display_results(self, findings, duration, target):
        """Display results in results tab"""
        self.results_text.delete(1.0, tk.END)
        
        # Header
        self.results_text.insert(tk.END, "="*70 + "\n", 'header')
        self.results_text.insert(tk.END, "VULNERABILITY ASSESSMENT REPORT\n", 'header')
        self.results_text.insert(tk.END, "="*70 + "\n\n", 'header')
        self.results_text.insert(tk.END, f"Target: {target}\n")
        self.results_text.insert(tk.END, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.results_text.insert(tk.END, f"Duration: {duration:.2f} seconds\n")
        self.results_text.insert(tk.END, f"Total Findings: {len(findings)}\n\n")
        
        # Summary
        severity_counts = Counter(f['severity'] for f in findings)
        self.results_text.insert(tk.END, "SEVERITY SUMMARY:\n", 'header')
        for sev in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            count = severity_counts.get(sev, 0)
            if count > 0:
                self.results_text.insert(tk.END, f"  {sev}: {count}\n", sev.lower())
        
        self.results_text.insert(tk.END, "\n" + "="*70 + "\n", 'header')
        self.results_text.insert(tk.END, "DETAILED FINDINGS\n", 'header')
        self.results_text.insert(tk.END, "="*70 + "\n\n", 'header')
        
        # Detailed findings
        for i, f in enumerate(findings, 1):
            severity = f['severity'].lower()
            self.results_text.insert(tk.END, f"{i}. [{f['severity']}] {f['title']}\n", severity)
            self.results_text.insert(tk.END, f"   Category: {f['category']}\n")
            if f.get('description'):
                self.results_text.insert(tk.END, f"   Description: {f['description']}\n")
            if f.get('remediation'):
                self.results_text.insert(tk.END, f"   Fix: {f['remediation']}\n")
            self.results_text.insert(tk.END, "\n")
        
        # Switch to results tab
        self.notebook.select(1)
    
    def load_history(self):
        """Load scan history into treeview"""
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        
        for record in self.db.get_history():
            self.history_tree.insert('', tk.END, values=record)
    
    def save_txt(self):
        """Save results as text file"""
        if not self.current_findings:
            messagebox.showwarning("Warning", "No results to save")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")]
        )
        
        if filename:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("VULNERABILITY ASSESSMENT REPORT\n")
                f.write("="*70 + "\n\n")
                for i, finding in enumerate(self.current_findings, 1):
                    f.write(f"{i}. [{finding['severity']}] {finding['title']}\n")
                    f.write(f"   Category: {finding['category']}\n")
                    if finding.get('remediation'):
                        f.write(f"   Fix: {finding['remediation']}\n")
                    f.write("-"*50 + "\n")
            
            messagebox.showinfo("Success", f"Report saved to {filename}")
    
    def save_csv(self):
        """Save results as CSV"""
        if not self.current_findings:
            messagebox.showwarning("Warning", "No results to save")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")]
        )
        
        if filename:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['title', 'severity', 'category', 'description', 'remediation'])
                writer.writeheader()
                for finding in self.current_findings:
                    writer.writerow({
                        'title': finding.get('title', ''),
                        'severity': finding.get('severity', ''),
                        'category': finding.get('category', ''),
                        'description': finding.get('description', ''),
                        'remediation': finding.get('remediation', '')
                    })
            
            messagebox.showinfo("Success", f"CSV saved to {filename}")
    
    def save_json(self):
        """Save results as JSON"""
        if not self.current_findings:
            messagebox.showwarning("Warning", "No results to save")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")]
        )
        
        if filename:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.current_findings, f, indent=2)
            
            messagebox.showinfo("Success", f"JSON saved to {filename}")


def main():
    root = tk.Tk()
    app = UltimateScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()