"""
DNS & NextDNS Settings Tab
Configure DNS-over-HTTPS and NextDNS integration
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QLabel,
    QPushButton, QComboBox, QLineEdit, QTextEdit, QCheckBox,
    QMessageBox, QTableWidget, QTableWidgetItem
)
from PySide6.QtCore import Qt

from network.nextdns_client import get_nextdns_client
from network.doh_resolver import get_doh_resolver, DoHProvider
from core.config import get_config


class DNSSettingsTab(QWidget):
    """DNS and NextDNS configuration tab"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        self.config = get_config()
        self.nextdns = get_nextdns_client()
        self.doh = get_doh_resolver()
        
        self.init_ui()
    
    def init_ui(self):
        """Initialize the UI"""
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(15, 15, 15, 15)
        
        # DNS-over-HTTPS Section
        doh_group = self.create_doh_section()
        layout.addWidget(doh_group)
        
        # NextDNS Section
        nextdns_group = self.create_nextdns_section()
        layout.addWidget(nextdns_group)
        
        layout.addStretch()
        
        self.setLayout(layout)
    
    def create_doh_section(self) -> QGroupBox:
        """Create DNS-over-HTTPS configuration section"""
        group = QGroupBox("🔒 DNS-over-HTTPS (Secure DNS)")
        group.setStyleSheet("""
            QGroupBox {
                font-size: 12pt;
                font-weight: bold;
                border: 2px solid #3498db;
                border-radius: 8px;
                margin-top: 12px;
                padding: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 8px;
            }
        """)
        
        layout = QVBoxLayout()
        
        # Enable/Disable DoH
        self.doh_enabled_check = QCheckBox("Enable DNS-over-HTTPS")
        self.doh_enabled_check.setChecked(self.config.get('dns.use_doh', False))
        self.doh_enabled_check.toggled.connect(self.on_doh_toggle)
        layout.addWidget(self.doh_enabled_check)
        
        # Provider selection
        provider_layout = QHBoxLayout()
        provider_layout.addWidget(QLabel("Provider:"))
        
        self.doh_provider_combo = QComboBox()
        providers = [
            ("Cloudflare (1.1.1.1)", "cloudflare"),
            ("Cloudflare Security", "cloudflare_security"),
            ("Quad9 (9.9.9.9)", "quad9"),
            ("Google DNS (8.8.8.8)", "google"),
            ("AdGuard DNS", "adguard"),
            ("AdGuard Family", "adguard_family")
        ]
        
        for name, value in providers:
            self.doh_provider_combo.addItem(name, value)
        
        # Set current provider
        current_provider = self.config.get('dns.provider', 'cloudflare')
        index = self.doh_provider_combo.findData(current_provider)
        if index >= 0:
            self.doh_provider_combo.setCurrentIndex(index)
        
        self.doh_provider_combo.currentIndexChanged.connect(self.on_provider_change)
        provider_layout.addWidget(self.doh_provider_combo)
        
        test_btn = QPushButton("Test Provider")
        test_btn.clicked.connect(self.test_doh_provider)
        provider_layout.addWidget(test_btn)
        
        provider_layout.addStretch()
        layout.addLayout(provider_layout)
        
        # Info text
        info_label = QLabel(
            "DNS-over-HTTPS encrypts your DNS queries for privacy and security. "
            "Recommended for enhanced protection against DNS hijacking and snooping."
        )
        info_label.setWordWrap(True)
        info_label.setStyleSheet("color: #7f8c8d; font-size: 9pt;")
        layout.addWidget(info_label)
        
        group.setLayout(layout)
        return group
    
    def create_nextdns_section(self) -> QGroupBox:
        """Create NextDNS configuration section"""
        group = QGroupBox("☁️ NextDNS Integration")
        group.setStyleSheet("""
            QGroupBox {
                font-size: 12pt;
                font-weight: bold;
                border: 2px solid #3498db;
                border-radius: 8px;
                margin-top: 12px;
                padding: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 8px;
            }
        """)
        
        layout = QVBoxLayout()
        
        # Profile ID input
        profile_layout = QHBoxLayout()
        profile_layout.addWidget(QLabel("Profile ID:"))
        
        self.nextdns_profile_input = QLineEdit()
        self.nextdns_profile_input.setPlaceholderText("Enter your 6-character NextDNS Profile ID")
        self.nextdns_profile_input.setText(self.config.get('nextdns.profile_id', ''))
        self.nextdns_profile_input.setMaxLength(6)
        profile_layout.addWidget(self.nextdns_profile_input)
        
        save_btn = QPushButton("Save")
        save_btn.clicked.connect(self.save_nextdns_profile)
        profile_layout.addWidget(save_btn)
        
        test_btn = QPushButton("Test Connection")
        test_btn.clicked.connect(self.test_nextdns_connection)
        profile_layout.addWidget(test_btn)
        
        layout.addLayout(profile_layout)
        
        # Fetch blocklists button
        fetch_layout = QHBoxLayout()
        
        fetch_btn = QPushButton("📥 Fetch Blocklists from NextDNS")
        fetch_btn.clicked.connect(self.fetch_nextdns_blocklists)
        fetch_layout.addWidget(fetch_btn)
        
        self.nextdns_status_label = QLabel("Not configured")
        self.nextdns_status_label.setStyleSheet("color: #95a5a6;")
        fetch_layout.addWidget(self.nextdns_status_label)
        
        fetch_layout.addStretch()
        layout.addLayout(fetch_layout)
        
        # Info
        info_label = QLabel(
            "NextDNS provides cloud-based blocklists including malware, ads, trackers, and more. "
            "Get your Profile ID from nextdns.io after creating an account."
        )
        info_label.setWordWrap(True)
        info_label.setStyleSheet("color: #7f8c8d; font-size: 9pt;")
        layout.addWidget(info_label)
        
        group.setLayout(layout)
        return group
    
    def on_doh_toggle(self, enabled: bool):
        """Handle DoH enable/disable"""
        self.config.set('dns.use_doh', enabled)
        self.config.save()
        
        status = "enabled" if enabled else "disabled"
        QMessageBox.information(
            self,
            "DNS-over-HTTPS",
            f"DNS-over-HTTPS has been {status}.\n\n"
            "Note: Changes may require application restart to take full effect."
        )
    
    def on_provider_change(self, index: int):
        """Handle provider selection change"""
        provider = self.doh_provider_combo.itemData(index)
        self.config.set('dns.provider', provider)
        self.config.save()
    
    def test_doh_provider(self):
        """Test selected DoH provider"""
        provider_data = self.doh_provider_combo.currentData()
        
        try:
            provider_enum = DoHProvider(provider_data)
            success, latency, message = self.doh.test_provider(provider_enum)
            
            if success:
                QMessageBox.information(
                    self,
                    "Provider Test",
                    f"✅ {message}\nLatency: {latency:.0f}ms"
                )
            else:
                QMessageBox.warning(
                    self,
                    "Provider Test",
                    f"❌ Test failed: {message}"
                )
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Test failed: {str(e)}"
            )
    
    def save_nextdns_profile(self):
        """Save NextDNS profile ID"""
        profile_id = self.nextdns_profile_input.text().strip()
        
        if len(profile_id) != 6:
            QMessageBox.warning(
                self,
                "Invalid Profile ID",
                "NextDNS Profile ID must be exactly 6 characters."
            )
            return
        
        self.config.set('nextdns.profile_id', profile_id)
        self.config.save()
        
        # Update NextDNS client
        self.nextdns.profile_id = profile_id
        
        self.nextdns_status_label.setText("Profile ID saved")
        self.nextdns_status_label.setStyleSheet("color: #27ae60;")
        
        QMessageBox.information(
            self,
            "NextDNS",
            "Profile ID saved successfully!"
        )
    
    def test_nextdns_connection(self):
        """Test NextDNS connection"""
        success, message = self.nextdns.test_connection()
        
        if success:
            self.nextdns_status_label.setText(f"✅ {message}")
            self.nextdns_status_label.setStyleSheet("color: #27ae60;")
            QMessageBox.information(self, "NextDNS", f"✅ {message}")
        else:
            self.nextdns_status_label.setText(f"❌ {message}")
            self.nextdns_status_label.setStyleSheet("color: #e74c3c;")
            QMessageBox.warning(self, "NextDNS", f"❌ {message}")
    
    def fetch_nextdns_blocklists(self):
        """Fetch blocklists from NextDNS"""
        if not self.nextdns.is_configured():
            QMessageBox.warning(
                self,
                "Not Configured",
                "Please configure and save your NextDNS Profile ID first."
            )
            return
        
        # Fetch blocklists
        from rules.blocklist_manager import get_blocklist_manager
        blocklist_manager = get_blocklist_manager()
        
        blocklists = self.nextdns.fetch_blocklists(force_refresh=True)
        
        if not blocklists:
            QMessageBox.warning(
                self,
                "No Data",
                "Could not fetch blocklists from NextDNS.\nCheck your Profile ID and internet connection."
            )
            return
        
        # Add to local blocklist
        added_count = 0
        for entry in blocklists:
            if entry['active']:
                domain = entry['domain']
                if blocklist_manager.add_domain(domain, category='nextdns'):
                    added_count += 1
        
        self.nextdns_status_label.setText(f"✅ Fetched {len(blocklists)} entries")
        self.nextdns_status_label.setStyleSheet("color: #27ae60;")
        
        QMessageBox.information(
            self,
            "Success",
            f"Fetched {len(blocklists)} entries from NextDNS.\n"
            f"Added {added_count} new domains to blocklist."
        )
