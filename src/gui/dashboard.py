"""
Main Dashboard for Defensiq Network Security
PySide6-based GUI with multiple tabs
"""

import sys
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QLabel, QPushButton, QTableWidget, QTableWidgetItem,
    QGroupBox, QGridLayout, QTextEdit, QMessageBox, QFileDialog,
    QComboBox, QSpinBox, QCheckBox, QFrame
)
from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QIcon, QAction

from core.config import get_config
from core.logger import get_logger, EventType
from network.monitor import get_network_monitor
from network.filter_engine import get_filter_engine, PYDIVERT_AVAILABLE
from rules.blocklist_manager import get_blocklist_manager, BlocklistCategory
from security.cia_monitor import get_cia_monitor
from gui.widgets import StatusIndicator, StatCard, SimpleChart, ToggleSwitch


class MainDashboard(QMainWindow):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        
        # Get instances
        self.config = get_config()
        self.logger = get_logger()
        self.monitor = get_network_monitor()
        self.filter_engine = get_filter_engine()
        self.blocklist = get_blocklist_manager()
        self.cia_monitor = get_cia_monitor()
        
        # Setup UI
        self.setWindowTitle("Defensiq Network Security")
        self.setGeometry(100, 100, 1200, 800)
        
        self.init_ui()
        
        # Setup update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_stats)
        self.update_timer.start(1000)  # Update every second
        
        # Apply theme
        self.apply_theme()
        
        self.logger.log_event(EventType.SERVICE_STARTED, "GUI launched", {})
        
        # Initial stats update
        self.update_stats()
    
    def init_ui(self):
        """Initialize user interface"""
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout()
        
        # Header
        header = self.create_header()
        layout.addWidget(header)
        
        # Tab widget
        self.tabs = QTabWidget()
        
        # Add tabs
        self.tabs.addTab(self.create_dashboard_tab(), "Dashboard")
        self.tabs.addTab(self.create_monitor_tab(), "Traffic Monitor")
        self.tabs.addTab(self.create_blocklist_tab(), "Blocklist")
        self.tabs.addTab(self.create_app_controls_tab(), "App Controls")
        self.tabs.addTab(self.create_dns_tab(), "DNS & NextDNS")
        self.tabs.addTab(self.create_diagnostics_tab(), "Diagnostics")
        self.tabs.addTab(self.create_logs_tab(), "Logs & Reports")
        self.tabs.addTab(self.create_settings_tab(), "Settings")
        
        layout.addWidget(self.tabs)
        
        central_widget.setLayout(layout)
        
        # Menu bar
        self.create_menu_bar()
    
    def create_header(self) -> QWidget:
        """Create header with app title and quick controls"""
        header = QWidget()
        header.setStyleSheet("""
            QWidget {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #2c3e50, stop:1 #3498db);
                border-radius: 8px;
                padding: 15px;
            }
        """)
        
        layout = QHBoxLayout()
        
        # Title
        title = QLabel("🛡️ Defensiq Network Security")
        title.setStyleSheet("""
            font-size: 22pt; 
            font-weight: bold; 
            color: white;
            background: transparent;
        """)
        layout.addWidget(title)
        
        layout.addStretch()
        
        # Status indicator
        status_container = QWidget()
        status_container.setStyleSheet("background: transparent;")
        status_layout = QHBoxLayout()
        status_layout.setContentsMargins(0, 0, 0, 0)
        status_layout.setSpacing(8)
        
        status_icon = QLabel("📊")
        status_icon.setStyleSheet("background: transparent; font-size: 14pt;")
        status_layout.addWidget(status_icon)
        
        self.filter_status_label = QLabel("Monitoring Active")
        self.filter_status_label.setStyleSheet("""
            font-size: 11pt;
            color: #ecf0f1;
            background: transparent;
            padding: 5px 10px;
        """)
        status_layout.addWidget(self.filter_status_label)
        
        status_container.setLayout(status_layout)
        layout.addWidget(status_container)
        
        # Filter toggle with label
        toggle_container = QWidget()
        toggle_container.setStyleSheet("background: transparent;")
        toggle_layout = QHBoxLayout()
        toggle_layout.setContentsMargins(0, 0, 0, 0)
        toggle_layout.setSpacing(10)
        
        filter_label = QLabel("Filtering:")
        filter_label.setStyleSheet("""
            font-size: 12pt;
            font-weight: bold;
            color: white;
            background: transparent;
        """)
        toggle_layout.addWidget(filter_label)
        
        self.filter_toggle = ToggleSwitch()
        self.filter_toggle.setChecked(self.config.get('filtering.enabled', False))
        self.filter_toggle.toggled.connect(self.on_filter_toggle)
        toggle_layout.addWidget(self.filter_toggle)
        
        toggle_container.setLayout(toggle_layout)
        layout.addWidget(toggle_container)
        
        header.setLayout(layout)
        return header
    
    def create_dashboard_tab(self) -> QWidget:
        """Create main dashboard tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(20)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Statistics Cards (make them bigger and more prominent)
        stats_group = QGroupBox("📊 Real-Time Network Statistics")
        stats_group.setStyleSheet("""
            QGroupBox {
                font-size: 13pt;
                font-weight: bold;
                border: 2px solid #3498db;
                border-radius: 10px;
                margin-top: 20px;
                padding-top: 25px;
                padding-left: 15px;
                padding-right: 15px;
                padding-bottom: 15px;
                background-color: #f0f6fc;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                left: 15px;
                top: 5px;
                padding: 0px 5px;
                color: #2c3e50;
                background-color: #f0f6fc;
            }
        """)
        stats_layout = QGridLayout()
        stats_layout.setSpacing(20)
        stats_layout.setContentsMargins(10, 10, 10, 10)
        
        self.stat_packets_sent = StatCard("📤 Packets Sent")
        self.stat_packets_recv = StatCard("📥 Packets Received")
        self.stat_blocked = StatCard("🚫 Blocked")
        self.stat_connections = StatCard("🔗 Active Connections")
        
        stats_layout.addWidget(self.stat_packets_sent, 0, 0)
        stats_layout.addWidget(self.stat_packets_recv, 0, 1)
        stats_layout.addWidget(self.stat_blocked, 0, 2)
        stats_layout.addWidget(self.stat_connections, 0, 3)
        
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        # Charts Section
        charts_group = QGroupBox("📈 Network Activity Trends")
        charts_group.setStyleSheet("""
            QGroupBox {
                font-size: 13pt;
                font-weight: bold;
                border: 2px solid #27ae60;
                border-radius: 10px;
                margin-top: 20px;
                padding-top: 25px;
                padding-left: 15px;
                padding-right: 15px;
                padding-bottom: 15px;
                background-color: #f0fdf4;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                left: 15px;
                top: 5px;
                padding: 0px 5px;
                color: #2c3e50;
                background-color: #f0fdf4;
            }
        """)
        charts_layout = QHBoxLayout()
        charts_layout.setSpacing(20)
        
        self.bandwidth_chart = SimpleChart("Bandwidth (Mbps)", 60)
        self.connections_chart = SimpleChart("Active Connections", 60)
        
        charts_layout.addWidget(self.bandwidth_chart)
        charts_layout.addWidget(self.connections_chart)
        
        charts_group.setLayout(charts_layout)
        layout.addWidget(charts_group)
        
        # Traffic Analysis Section
        analysis_group = QGroupBox("🔍 Traffic Analysis")
        analysis_group.setStyleSheet("""
            QGroupBox {
                font-size: 13pt;
                font-weight: bold;
                border: 2px solid #9b59b6;
                border-radius: 10px;
                margin-top: 20px;
                padding-top: 25px;
                padding-left: 15px;
                padding-right: 15px;
                padding-bottom: 15px;
                background-color: #f9f0ff;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                left: 15px;
                top: 5px;
                padding: 0px 5px;
                color: #2c3e50;
                background-color: #f9f0ff;
            }
        """)
        protocol_layout = QHBoxLayout()
        protocol_layout.setSpacing(20)
        
        from gui.widgets import PieChart
        self.protocol_pie = PieChart("🔀 Traffic by Protocol")
        self.blocked_pie = PieChart("🛡️ Allowed vs Blocked")
        
        protocol_layout.addWidget(self.protocol_pie)
        protocol_layout.addWidget(self.blocked_pie)
        
        analysis_group.setLayout(protocol_layout)
        layout.addWidget(analysis_group)
        
        layout.addStretch()
        
        tab.setLayout(layout)
        return tab
    
    def create_monitor_tab(self) -> QWidget:
        """Create traffic monitoring tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Controls
        controls_layout = QHBoxLayout()
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_connections)
        controls_layout.addWidget(refresh_btn)
        
        controls_layout.addStretch()
        
        layout.addLayout(controls_layout)
        
        # Connection table
        self.connection_table = QTableWidget()
        self.connection_table.setColumnCount(5)
        self.connection_table.setHorizontalHeaderLabels([
            "Local Address", "Remote Address", "Status", "Process", "Timestamp"
        ])
        
        layout.addWidget(self.connection_table)
        
        tab.setLayout(layout)
        return tab
    
    def create_blocklist_tab(self) -> QWidget:
        """Create blocklist management tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Controls
        controls_layout = QHBoxLayout()
        
        add_domain_btn = QPushButton("Add Domain")
        add_domain_btn.clicked.connect(self.add_domain_dialog)
        controls_layout.addWidget(add_domain_btn)
        
        add_ip_btn = QPushButton("Add IP")
        add_ip_btn.clicked.connect(self.add_ip_dialog)
        controls_layout.addWidget(add_ip_btn)
        
        import_btn = QPushButton("Import List")
        import_btn.clicked.connect(self.import_blocklist)
        controls_layout.addWidget(import_btn)
        
        export_btn = QPushButton("Export List")
        export_btn.clicked.connect(self.export_blocklist)
        controls_layout.addWidget(export_btn)
        
        controls_layout.addStretch()
        
        layout.addLayout(controls_layout)
        
        # Statistics
        stats_label = QLabel()
        self.blocklist_stats_label = stats_label
        layout.addWidget(stats_label)
        
        # Blocklist table
        self.blocklist_table = QTableWidget()
        self.blocklist_table.setColumnCount(3)
        self.blocklist_table.setHorizontalHeaderLabels(["Type", "Value", "Category"])
        
        layout.addWidget(self.blocklist_table)
        
        # Update blocklist display
        self.refresh_blocklist()
        
        tab.setLayout(layout)
        return tab
    
    def create_app_controls_tab(self) -> QWidget:
        """Create application controls tab"""
        from gui.app_control_tab import ApplicationControlsTab
        return ApplicationControlsTab()
    
    def create_dns_tab(self) -> QWidget:
        """Create DNS & NextDNS configuration tab"""
        from gui.dns_tab import DNSSettingsTab
        return DNSSettingsTab()
    
    def create_diagnostics_tab(self) -> QWidget:
        """Create diagnostics tab"""
        from gui.diagnostics_tab import DiagnosticsTab
        return DiagnosticsTab()
    
    def create_logs_tab(self) -> QWidget:
        """Create logs and reports tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Controls
        controls_layout = QHBoxLayout()
        
        export_btn = QPushButton("Export Logs")
        export_btn.clicked.connect(self.export_logs)
        controls_layout.addWidget(export_btn)
        
        clear_btn = QPushButton("Clear Display")
        clear_btn.clicked.connect(self.clear_log_display)
        controls_layout.addWidget(clear_btn)
        
        controls_layout.addStretch()
        
        layout.addLayout(controls_layout)
        
        # Log display
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setStyleSheet("font-family: 'Courier New'; font-size: 10pt;")
        
        layout.addWidget(self.log_display)
        
        tab.setLayout(layout)
        return tab
    
    def create_settings_tab(self) -> QWidget:
        """Create settings tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Theme settings
        theme_group = QGroupBox("Appearance")
        theme_layout = QHBoxLayout()
        
        theme_layout.addWidget(QLabel("Theme:"))
        
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Light", "Dark"])
        self.theme_combo.setCurrentText(self.config.get('app.theme', 'light').capitalize())
        self.theme_combo.currentTextChanged.connect(self.on_theme_change)
        theme_layout.addWidget(self.theme_combo)
        
        theme_layout.addStretch()
        
        theme_group.setLayout(theme_layout)
        layout.addWidget(theme_group)
        
        # Monitoring settings
        monitoring_group = QGroupBox("Monitoring")
        monitoring_layout = QVBoxLayout()
        
        self.log_all_traffic_check = QCheckBox("Log all traffic (not just blocked)")
        self.log_all_traffic_check.setChecked(
            self.config.get('monitoring.log_all_traffic', False)
        )
        self.log_all_traffic_check.toggled.connect(
            lambda checked: self.config.set('monitoring.log_all_traffic', checked)
        )
        monitoring_layout.addWidget(self.log_all_traffic_check)
        
        monitoring_group.setLayout(monitoring_layout)
        layout.addWidget(monitoring_group)
        
        # CIA Triad settings
        cia_group = QGroupBox("CIA Triad")
        cia_layout = QVBoxLayout()
        
        cia_layout.addWidget(QLabel("DoS Detection Threshold (packets/sec):"))
        
        self.dos_threshold_spin = QSpinBox()
        self.dos_threshold_spin.setRange(100, 10000)
        self.dos_threshold_spin.setValue(self.config.get('cia_triad.dos_threshold', 1000))
        self.dos_threshold_spin.valueChanged.connect(
            lambda value: self.config.set('cia_triad.dos_threshold', value)
        )
        cia_layout.addWidget(self.dos_threshold_spin)
        
        cia_group.setLayout(cia_layout)
        layout.addWidget(cia_group)
        
        layout.addStretch()
        
        # Save button
        save_btn = QPushButton("Save Settings")
        save_btn.clicked.connect(self.save_settings)
        layout.addWidget(save_btn)
        
        tab.setLayout(layout)
        return tab
    
    def create_menu_bar(self):
        """Create menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        
        export_config_action = QAction("Export Configuration", self)
        export_config_action.triggered.connect(self.export_config)
        file_menu.addAction(export_config_action)
        
        import_config_action = QAction("Import Configuration", self)
        import_config_action.triggered.connect(self.import_config)
        file_menu.addAction(import_config_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Help menu
        help_menu = menubar.addMenu("Help")
        
        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def update_stats(self):
        """Update dashboard statistics"""
        try:
            # Update network stats
            stats = self.monitor.update()
            
            # Update stat cards with safe defaults
            self.stat_packets_sent.set_value(
                f"{stats.get('packets_sent', 0):,}",
                f"{stats.get('bandwidth_sent_mbps', 0):.2f} Mbps"
            )
            
            self.stat_packets_recv.set_value(
                f"{stats.get('packets_recv', 0):,}",
                f"{stats.get('bandwidth_recv_mbps', 0):.2f} Mbps"
            )
            
            self.stat_connections.set_value(
                str(stats.get('connections_active', 0))
            )
            
            # Update filter stats if running
            if self.filter_engine.running:
                try:
                    filter_stats = self.filter_engine.get_stats()
                    self.stat_blocked.set_value(str(filter_stats.get('packets_blocked', 0)))
                except:
                    self.stat_blocked.set_value("0")
            else:
                self.stat_blocked.set_value("--")
            
            # Update charts
            total_bandwidth = stats.get('bandwidth_sent_mbps', 0) + stats.get('bandwidth_recv_mbps', 0)
            self.bandwidth_chart.add_data_point(total_bandwidth)
            self.connections_chart.add_data_point(stats.get('connections_active', 0))
            
            # Update pie charts with actual data
            # Protocol distribution - use actual connection data
            protocol_data = {
                'TCP': stats.get('tcp_count', 70),
                'UDP': stats.get('udp_count', 25),
                'Other': stats.get('other_count', 5)
            }
            self.protocol_pie.update_chart(protocol_data)
            
            # Blocked vs Allowed
            if self.filter_engine.running:
                try:
                    filter_stats = self.filter_engine.get_stats()
                    total = filter_stats.get('packets_allowed', 0) + filter_stats.get('packets_blocked', 0)
                    if total > 0:
                        blocked_data = {
                            'Allowed': filter_stats.get('packets_allowed', 0),
                            'Blocked': filter_stats.get('packets_blocked', 0)
                        }
                        self.blocked_pie.update_chart(blocked_data)
                    else:
                        self.blocked_pie.update_chart({'Filtering Active': 100})
                except:
                    self.blocked_pie.update_chart({'Filtering Active': 100})
            else:
                self.blocked_pie.update_chart({'Monitoring Only': 100})
            
            # Update logs display
            self.update_log_display()
            
        except Exception as e:
            # Log error but don't crash
            print(f"Error updating stats: {e}")
    
    def refresh_connections(self):
        """Refresh connection table"""
        connections = self.monitor.get_active_connections(100)
        
        self.connection_table.setRowCount(len(connections))
        
        for i, conn in enumerate(connections):
            self.connection_table.setItem(i, 0, QTableWidgetItem(conn.get('local_addr', 'N/A')))
            self.connection_table.setItem(i, 1, QTableWidgetItem(conn.get('remote_addr', 'N/A')))
            self.connection_table.setItem(i, 2, QTableWidgetItem(conn.get('status', 'N/A')))
            self.connection_table.setItem(i, 3, QTableWidgetItem(conn.get('process', 'Unknown')))
            self.connection_table.setItem(i, 4, QTableWidgetItem(conn.get('timestamp', 'N/A')))
    
    def refresh_blocklist(self):
        """Refresh blocklist table"""
        # Update statistics
        stats = self.blocklist.get_statistics()
        self.blocklist_stats_label.setText(
            f"Total: {stats['total_domains']} domains, {stats['total_ips']} IPs"
        )
        
        # Update table
        row_count = stats['total_domains'] + stats['total_ips']
        self.blocklist_table.setRowCount(row_count)
        
        row = 0
        
        # Add domains
        for domain, category in self.blocklist.blocked_domains.items():
            self.blocklist_table.setItem(row, 0, QTableWidgetItem("Domain"))
            self.blocklist_table.setItem(row, 1, QTableWidgetItem(domain))
            self.blocklist_table.setItem(row, 2, QTableWidgetItem(category))
            row += 1
        
        # Add IPs
        for ip, category in self.blocklist.blocked_ips.items():
            self.blocklist_table.setItem(row, 0, QTableWidgetItem("IP"))
            self.blocklist_table.setItem(row, 1, QTableWidgetItem(ip))
            self.blocklist_table.setItem(row, 2, QTableWidgetItem(category))
            row += 1
    
    def update_log_display(self):
        """Update log display with recent events"""
        events = self.logger.get_recent_events(50)
        
        # Only update if there are new events
        if events:
            self.log_display.clear()
            for event in reversed(events):
                timestamp = event['timestamp']
                event_type = event['type']
                message = event['message']
                
                self.log_display.append(f"[{timestamp}] {event_type}: {message}")
    
    def on_filter_toggle(self, enabled: bool):
        """Handle filter toggle"""
        if not PYDIVERT_AVAILABLE:
            QMessageBox.warning(
                self,
                "PyDivert Not Available",
                "PyDivert is not installed. Filtering cannot be enabled.\n\n"
                "Install with: pip install pydivert"
            )
            self.filter_toggle.setChecked(False)
            return
        
        self.config.set('filtering.enabled', enabled)
        
        if enabled:
            success = self.filter_engine.start()
            
            if not success:
                QMessageBox.critical(
                    self,
                    "Failed to Start Filtering",
                    "Could not start the filtering engine.\n\n"
                    "Make sure you:\n"
                    "1. Run as Administrator\n"
                    "2. Have PyDivert installed\n"
                    "3. No other packet filter is running"
                )
                self.filter_toggle.setChecked(False)
                self.filter_status_label.setText("Monitoring Active")
                self.filter_status_label.setStyleSheet("""
                    font-size: 11pt;
                    color: #ecf0f1;
                    background: transparent;
                    padding: 5px 15px;
                """)
                return
            
            self.filter_status_label.setText("🛡️ Filtering Active")
            self.filter_status_label.setStyleSheet("""
                font-size: 11pt;
                color: #2ecc71;
                background: transparent;
                padding: 5px 15px;
                font-weight: bold;
            """)
            
            self.logger.log_event(
                EventType.CONFIG_CHANGED,
                "Packet filtering enabled",
                {}
            )
        else:
            self.filter_engine.stop()
            self.filter_status_label.setText("Monitoring Active")
            self.filter_status_label.setStyleSheet("""
                font-size: 11pt;
                color: #ecf0f1;
                background: transparent;
                padding: 5px 15px;
            """)
            
            self.logger.log_event(
                EventType.CONFIG_CHANGED,
                "Packet filtering disabled",
                {}
            )
    
    def add_domain_dialog(self):
        """Show dialog to add domain"""
        from PySide6.QtWidgets import QInputDialog
        
        domain, ok = QInputDialog.getText(
            self, "Add Domain", "Enter domain to block:"
        )
        
        if ok and domain:
            if self.blocklist.add_domain(domain):
                self.refresh_blocklist()
                QMessageBox.information(self, "Success", f"Added domain: {domain}")
            else:
                QMessageBox.warning(self, "Error", "Failed to add domain")
    
    def add_ip_dialog(self):
        """Show dialog to add IP"""
        from PySide6.QtWidgets import QInputDialog
        
        ip, ok = QInputDialog.getText(
            self, "Add IP", "Enter IP address to block:"
        )
        
        if ok and ip:
            if self.blocklist.add_ip(ip):
                self.refresh_blocklist()
                QMessageBox.information(self, "Success", f"Added IP: {ip}")
            else:
                QMessageBox.warning(self, "Error", "Invalid IP address")
    
    def import_blocklist(self):
        """Import blocklist from file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Import Blocklist",
            "",
            "All Files (*.txt *.json);;Text Files (*.txt);;JSON Files (*.json)"
        )
        
        if file_path:
            count = self.blocklist.import_from_file(file_path)
            self.refresh_blocklist()
            QMessageBox.information(
                self, "Import Complete", f"Imported {count} entries"
            )
    
    def export_blocklist(self):
        """Export blocklist to file"""
        file_path, selected_filter = QFileDialog.getSaveFileName(
            self,
            "Export Blocklist",
            "blocklist.json",
            "JSON Files (*.json);;Text Files (*.txt)"
        )
        
        if file_path:
            format = 'json' if 'json' in selected_filter.lower() else 'txt'
            if self.blocklist.export_to_file(file_path, format):
                QMessageBox.information(self, "Success", "Blocklist exported")
            else:
                QMessageBox.warning(self, "Error", "Failed to export blocklist")
    
    def export_logs(self):
        """Export logs to file"""
        file_path, selected_filter = QFileDialog.getSaveFileName(
            self,
            "Export Logs",
            "defensiq_logs.csv",
            "CSV Files (*.csv);;JSON Files (*.json);;Text Files (*.txt)"
        )
        
        if file_path:
            format = 'csv'
            if 'json' in selected_filter.lower():
                format = 'json'
            elif 'txt' in selected_filter.lower():
                format = 'txt'
            
            if self.logger.export_logs(file_path, format):
                QMessageBox.information(self, "Success", "Logs exported")
            else:
                QMessageBox.warning(self, "Error", "Failed to export logs")
    
    def clear_log_display(self):
        """Clear log display"""
        self.log_display.clear()
    
    def save_settings(self):
        """Save all settings"""
        if self.config.save():
            QMessageBox.information(self, "Success", "Settings saved")
        else:
            QMessageBox.warning(self, "Error", "Failed to save settings")
    
    def export_config(self):
        """Export configuration"""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Configuration", "defensiq_config.json", "JSON Files (*.json)"
        )
        
        if file_path:
            if self.config.export_config(file_path):
                QMessageBox.information(self, "Success", "Configuration exported")
            else:
                QMessageBox.warning(self, "Error", "Failed to export configuration")
    
    def import_config(self):
        """Import configuration"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Import Configuration", "", "JSON Files (*.json)"
        )
        
        if file_path:
            if self.config.import_config(file_path):
                QMessageBox.information(
                    self, "Success", "Configuration imported. Restart required."
                )
            else:
                QMessageBox.warning(self, "Error", "Failed to import configuration")
    
    def on_theme_change(self, theme: str):
        """Handle theme change"""
        self.config.set('app.theme', theme.lower())
        self.apply_theme()
    
    def apply_theme(self):
        """Apply theme to application"""
        theme = self.config.get('app.theme', 'light')
        
        if theme == 'dark':
            self.setStyleSheet("""
                QMainWindow, QWidget {
                    background-color: #2c3e50;
                    color: #ecf0f1;
                }
                QGroupBox {
                    border: 1px solid #34495e;
                    margin-top: 10px;
                    font-weight: bold;
                }
                QGroupBox::title {
                    subcontrol-origin: margin;
                    left: 10px;
                    padding: 0 5px;
                }
                QTableWidget {
                    background-color: #34495e;
                    alternate-background-color: #2c3e50;
                    color: #ecf0f1;
                }
                QPushButton {
                    background-color: #3498db;
                    color: white;
                    padding: 5px 15px;
                    border-radius: 3px;
                }
                QPushButton:hover {
                    background-color: #2980b9;
                }
            """)
        else:
            self.setStyleSheet("")
    
    def show_about(self):
        """Show about dialog"""
        QMessageBox.about(
            self,
            "About Defensiq Network Security",
            "<h2>Defensiq Network Security</h2>"
            "<p>Version 1.0.0</p>"
            "<p>Ethical Windows Network Security Application</p>"
            "<p><b>Features:</b></p>"
            "<ul>"
            "<li>Real-time network monitoring</li>"
            "<li>Domain/IP blocking</li>"
            "<li>CIA Triad security monitoring</li>"
            "<li>Comprehensive logging</li>"
            "</ul>"
            "<p><b>⚠️ Important:</b> All filtering requires administrator privileges "
            "and PyDivert driver installation.</p>"
        )


def launch_gui(debug: bool = False):
    """Launch the GUI application"""
    app = QApplication(sys.argv)
    app.setApplicationName("Defensiq Network Security")
    
    window = MainDashboard()
    window.show()
    
    sys.exit(app.exec())
