"""
Diagnostics Tab
Network health checks and automated repairs
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QLabel,
    QPushButton, QTextEdit, QProgressBar, QMessageBox
)
from PySide6.QtCore import Qt, QThread, Signal

from utils.diagnostics import get_diagnostics


class DiagnosticsThread(QThread):
    """Background thread for running diagnostics"""
    
    finished = Signal(dict)
    progress = Signal(str)
    
    def __init__(self, diagnostics):
        super().__init__()
        self.diagnostics = diagnostics
    
    def run(self):
        """Run diagnostics"""
        self.progress.emit("Starting diagnostics...")
        results = self.diagnostics.run_full_check()
        self.finished.emit(results)


class DiagnosticsTab(QWidget):
    """Network diagnostics and repair tab"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        self.diagnostics = get_diagnostics()
        self.diagnostic_thread = None
        
        self.init_ui()
    
    def init_ui(self):
        """Initialize the UI"""
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(15, 15, 15, 15)
        
        # Header with run button
        header_layout = QHBoxLayout()
        
        title = QLabel("🔧 Network Diagnostics & Repair")
        title.setStyleSheet("font-size: 14pt; font-weight: bold;")
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        self.run_btn = QPushButton("🔍 Run Full Check")
        self.run_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                padding: 10px 20px;
                font-size: 11pt;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        self.run_btn.clicked.connect(self.run_diagnostics)
        header_layout.addWidget(self.run_btn)
        
        layout.addLayout(header_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Results display
        results_group = QGroupBox("Diagnostic Results")
        results_layout = QVBoxLayout()
        
        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)
        self.results_display.setStyleSheet("font-family: 'Courier New'; font-size: 10pt;")
        self.results_display.setPlainText("Click 'Run Full Check' to start diagnostics...")
        results_layout.addWidget(self.results_display)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        # Repair tools
        repair_group = QGroupBox("🔧 Repair Tools")
        repair_layout = QHBoxLayout()
        
        repair_dns_btn = QPushButton("Reset DNS")
        repair_dns_btn.clicked.connect(self.repair_dns)
        repair_layout.addWidget(repair_dns_btn)
        
        repair_firewall_btn = QPushButton("Reset Firewall")
        repair_firewall_btn.clicked.connect(self.repair_firewall)
        repair_layout.addWidget(repair_firewall_btn)
        
        repair_hosts_btn = QPushButton("Repair HOSTS File")
        repair_hosts_btn.clicked.connect(self.repair_hosts)
        repair_layout.addWidget(repair_hosts_btn)
        
        repair_layout.addStretch()
        
        repair_group.setLayout(repair_layout)
        layout.addWidget(repair_group)
        
        self.setLayout(layout)
    
    def run_diagnostics(self):
        """Run full diagnostic check"""
        self.run_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.results_display.setPlainText("Running diagnostics...\n\n")
        
        # Run in background thread
        self.diagnostic_thread = DiagnosticsThread(self.diagnostics)
        self.diagnostic_thread.finished.connect(self.on_diagnostics_complete)
        self.diagnostic_thread.progress.connect(self.on_progress)
        self.diagnostic_thread.start()
    
    def on_progress(self, message: str):
        """Update progress"""
        self.results_display.append(message)
    
    def on_diagnostics_complete(self, results: dict):
        """Handle diagnostics completion"""
        self.run_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        
        # Display results
        output = "=== DIAGNOSTIC RESULTS ===\n\n"
        
        for check_name, result in results.items():
            status_icon = {
                'ok': '✅',
                'warning': '⚠️',
                'error': '❌'
            }.get(result.get('status', 'error'), '❓')
            
            output += f"{status_icon} {check_name.replace('_', ' ').title()}\n"
            output += f"   Status: {result.get('status', 'unknown').upper()}\n"
            output += f"   Message: {result.get('message', 'No details')}\n\n"
        
        # Summary
        ok_count = sum(1 for r in results.values() if r.get('status') == 'ok')
        warning_count = sum(1 for r in results.values() if r.get('status') == 'warning')
        error_count = sum(1 for r in results.values() if r.get('status') == 'error')
        
        output += f"\n=== SUMMARY ===\n"
        output += f"✅ OK: {ok_count}\n"
        output += f"⚠️ Warnings: {warning_count}\n"
        output += f"❌ Errors: {error_count}\n"
        
        if error_count == 0 and warning_count == 0:
            output += "\n🎉 All systems operational!"
        elif error_count > 0:
            output += "\n⚠️ Some issues detected. Use repair tools if needed."
        
        self.results_display.setPlainText(output)
    
    def repair_dns(self):
        """Repair DNS settings"""
        reply = QMessageBox.question(
            self,
            "Reset DNS",
            "This will reset DNS settings to automatic.\nContinue?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            success, message = self.diagnostics.repair_dns()
            
            if success:
                QMessageBox.information(self, "Success", message)
            else:
                QMessageBox.critical(self, "Error", message)
    
    def repair_firewall(self):
        """Repair firewall settings"""
        reply = QMessageBox.question(
            self,
            "Reset Firewall",
            "This will reset Windows Firewall to default settings.\n"
            "ALL custom rules will be removed!\n\n"
            "Continue?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            success, message = self.diagnostics.repair_firewall()
            
            if success:
                QMessageBox.information(self, "Success", message)
            else:
                QMessageBox.critical(self, "Error", message)
    
    def repair_hosts(self):
        """Repair HOSTS file"""
        reply = QMessageBox.question(
            self,
            "Repair HOSTS File",
            "This will restore the default HOSTS file.\n"
            "A backup will be created.\n\n"
            "Continue?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            success, message = self.diagnostics.repair_hosts_file()
            
            if success:
                QMessageBox.information(self, "Success", message)
            else:
                QMessageBox.critical(self, "Error", message)
