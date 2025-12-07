"""
Application Controls Tab
Manage network access for individual applications
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QLabel,
    QPushButton, QTableWidget, QTableWidgetItem, QMessageBox,
    QInputDialog, QHeaderView
)
from PySide6.QtCore import Qt, QTimer

from network.app_control import get_app_control


class ApplicationControlsTab(QWidget):
    """Application network controls tab"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        self.app_control = get_app_control()
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_processes)
        
        self.init_ui()
    
    def init_ui(self):
        """Initialize the UI"""
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(15, 15, 15, 15)
        
        # Header
        header_layout = QHBoxLayout()
        
        title = QLabel("🎯 Application Network Controls")
        title.setStyleSheet("font-size: 14pt; font-weight: bold;")
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        # Refresh button
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self.refresh_all)
        header_layout.addWidget(refresh_btn)
        
        layout.addLayout(header_layout)
        
        # Running Processes Section
        processes_group = QGroupBox("📱 Running Processes with Network Activity")
        processes_layout = QVBoxLayout()
        
        self.processes_table = QTableWidget()
        self.processes_table.setColumnCount(4)
        self.processes_table.setHorizontalHeaderLabels([
            "Application", "PID", "Connections", "Status"
        ])
        self.processes_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.processes_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.processes_table.doubleClicked.connect(self.on_process_double_click)
        
        processes_layout.addWidget(self.processes_table)
        
        # Quick action buttons
        process_actions = QHBoxLayout()
        
        block_btn = QPushButton("🚫 Block Selected App")
        block_btn.clicked.connect(self.block_selected_app)
        process_actions.addWidget(block_btn)
        
        allow_btn = QPushButton("✅ Allow Selected App")
        allow_btn.clicked.connect(self.allow_selected_app)
        process_actions.addWidget(allow_btn)
        
        process_actions.addStretch()
        
        processes_layout.addLayout(process_actions)
        processes_group.setLayout(processes_layout)
        layout.addWidget(processes_group)
        
        # Application Rules Section
        rules_group = QGroupBox("📋 Application Rules")
        rules_layout = QVBoxLayout()
        
        self.rules_table = QTableWidget()
        self.rules_table.setColumnCount(4)
        self.rules_table.setHorizontalHeaderLabels([
            "Application", "Action", "Bandwidth Limit", "Enabled"
        ])
        self.rules_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.rules_table.setSelectionBehavior(QTableWidget.SelectRows)
        
        rules_layout.addWidget(self.rules_table)
        
        # Rule management buttons
        rule_actions = QHBoxLayout()
        
        add_rule_btn = QPushButton("➕ Add Rule")
        add_rule_btn.clicked.connect(self.add_rule_dialog)
        rule_actions.addWidget(add_rule_btn)
        
        remove_rule_btn = QPushButton("➖ Remove Rule")
        remove_rule_btn.clicked.connect(self.remove_selected_rule)
        rule_actions.addWidget(remove_rule_btn)
        
        toggle_rule_btn = QPushButton("🔄 Toggle Rule")
        toggle_rule_btn.clicked.connect(self.toggle_selected_rule)
        rule_actions.addWidget(toggle_rule_btn)
        
        rule_actions.addStretch()
        
        # Statistics
        self.stats_label = QLabel()
        self.stats_label.setStyleSheet("font-size: 10pt; color: #7f8c8d;")
        rule_actions.addWidget(self.stats_label)
        
        rules_layout.addLayout(rule_actions)
        rules_group.setLayout(rules_layout)
        layout.addWidget(rules_group)
        
        self.setLayout(layout)
        
        # Initial load
        self.refresh_all()
        
        # Auto-refresh every 3 seconds
        self.refresh_timer.start(3000)
    
    def refresh_all(self):
        """Refresh all data"""
        self.refresh_processes()
        self.refresh_rules()
        self.update_statistics()
    
    def refresh_processes(self):
        """Refresh running processes list"""
        processes = self.app_control.get_running_processes()
        
        self.processes_table.setRowCount(len(processes))
        
        for i, proc in enumerate(processes):
            # Application name
            app_item = QTableWidgetItem(proc['name'])
            if proc['blocked']:
                app_item.setForeground(Qt.red)
            self.processes_table.setItem(i, 0, app_item)
            
            # PID
            self.processes_table.setItem(i, 1, QTableWidgetItem(str(proc['pid'])))
            
            # Connections count
            self.processes_table.setItem(i, 2, QTableWidgetItem(str(proc['connections_count'])))
            
            # Status
            status = "🚫 BLOCKED" if proc['blocked'] else "✅ Allowed"
            status_item = QTableWidgetItem(status)
            if proc['blocked']:
                status_item.setForeground(Qt.red)
            self.processes_table.setItem(i, 3, status_item)
    
    def refresh_rules(self):
        """Refresh application rules list"""
        rules = self.app_control.get_all_rules()
        
        self.rules_table.setRowCount(len(rules))
        
        for i, rule in enumerate(rules):
            # Application name
            self.rules_table.setItem(i, 0, QTableWidgetItem(rule.process_name))
            
            # Action
            action_text = "🚫 Block" if rule.action == 'block' else "✅ Allow"
            action_item = QTableWidgetItem(action_text)
            if rule.action == 'block':
                action_item.setForeground(Qt.red)
            self.rules_table.setItem(i, 1, action_item)
            
            # Bandwidth limit
            limit_text = f"{rule.bandwidth_limit_kbps} kbps" if rule.bandwidth_limit_kbps else "No limit"
            self.rules_table.setItem(i, 2, QTableWidgetItem(limit_text))
            
            # Enabled
            enabled_text = "✓ Enabled" if rule.enabled else "✗ Disabled"
            enabled_item = QTableWidgetItem(enabled_text)
            if not rule.enabled:
                enabled_item.setForeground(Qt.gray)
            self.rules_table.setItem(i, 3, enabled_item)
    
    def update_statistics(self):
        """Update statistics display"""
        stats = self.app_control.get_statistics()
        
        self.stats_label.setText(
            f"Total Rules: {stats['total_rules']} | "
            f"Active: {stats['active_rules']} | "
            f"Blocked Apps: {stats['blocked_apps']}"
        )
    
    def on_process_double_click(self, index):
        """Handle process double-click"""
        row = index.row()
        app_name = self.processes_table.item(row, 0).text()
        
        # Show options
        reply = QMessageBox.question(
            self,
            "Quick Action",
            f"What would you like to do with {app_name}?",
            QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel,
            QMessageBox.Cancel
        )
        
        if reply == QMessageBox.Yes:
            self.app_control.add_rule(app_name, 'block')
            self.refresh_all()
            QMessageBox.information(self, "Success", f"Blocked {app_name}")
        elif reply == QMessageBox.No:
            self.app_control.remove_rule(app_name)
            self.refresh_all()
            QMessageBox.information(self, "Success", f"Removed block for {app_name}")
    
    def block_selected_app(self):
        """Block the selected application"""
        current_row = self.processes_table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "No Selection", "Please select an application first.")
            return
        
        app_name = self.processes_table.item(current_row, 0).text()
        
        self.app_control.add_rule(app_name, 'block')
        self.refresh_all()
        QMessageBox.information(self, "Success", f"Added block rule for {app_name}")
    
    def allow_selected_app(self):
        """Allow the selected application (remove block)"""
        current_row = self.processes_table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "No Selection", "Please select an application first.")
            return
        
        app_name =self.processes_table.item(current_row, 0).text()
        
        self.app_control.remove_rule(app_name)
        self.refresh_all()
        QMessageBox.information(self, "Success", f"Removed block rule for {app_name}")
    
    def add_rule_dialog(self):
        """Show dialog to add a new rule"""
        app_name, ok = QInputDialog.getText(
            self, "Add Rule", "Enter application name (e.g., chrome.exe):"
        )
        
        if not ok or not app_name:
            return
        
        # Ask for action
        reply = QMessageBox.question(
            self,
            "Rule Action",
            f"Block {app_name}?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes
        )
        
        action = 'block' if reply == QMessageBox.Yes else 'allow'
        
        self.app_control.add_rule(app_name, action)
        self.refresh_all()
        QMessageBox.information(self, "Success", f"Added rule for {app_name}")
    
    def remove_selected_rule(self):
        """Remove the selected rule"""
        current_row = self.rules_table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "No Selection", "Please select a rule first.")
            return
        
        app_name = self.rules_table.item(current_row, 0).text()
        
        reply = QMessageBox.question(
            self,
            "Confirm",
            f"Remove rule for {app_name}?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.app_control.remove_rule(app_name)
            self.refresh_all()
            QMessageBox.information(self, "Success", f"Removed rule for {app_name}")
    
    def toggle_selected_rule(self):
        """Toggle the selected rule's enabled state"""
        current_row = self.rules_table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "No Selection", "Please select a rule first.")
            return
        
        app_name = self.rules_table.item(current_row, 0).text()
        rule = self.app_control.get_rule(app_name)
        
        if rule:
            new_state = not rule.enabled
            self.app_control.toggle_rule(app_name, new_state)
            self.refresh_all()
            
            status = "enabled" if new_state else "disabled"
            QMessageBox.information(self, "Success", f"Rule for {app_name} {status}")
