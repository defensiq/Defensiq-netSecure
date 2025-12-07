"""
System Tray Integration for Defensiq
Provides quick access to core functions from system tray
"""

from PySide6.QtWidgets import QSystemTrayIcon, QMenu
from PySide6.QtGui import QIcon, QAction
from PySide6.QtCore import Signal

from core.config import get_config
from core.logger import get_logger, EventType


class DefensiqTrayIcon(QSystemTrayIcon):
    """System tray icon with menu"""
    
    # Signals
    show_dashboard_signal = Signal()
    toggle_filtering_signal = Signal(bool)
    exit_signal = Signal()
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        self.config = get_config()
        self.logger = get_logger()
        
        # Set icon (using default for now - would use custom icon in production)
        # self.setIcon(QIcon("assets/icon.png"))
        self.setToolTip("Defensiq Network Security")
        
        # Create menu
        self.create_menu()
        
        # Connect signals
        self.activated.connect(self.on_activated)
        
        # Show tray icon
        self.show()
        
        self.logger.log_event(EventType.SERVICE_STARTED, "System tray icon created", {})
    
    def create_menu(self):
        """Create context menu"""
        menu = QMenu()
        
        # Dashboard action
        show_action = QAction("Show Dashboard", self)
        show_action.triggered.connect(lambda: self.show_dashboard_signal.emit())
        menu.addAction(show_action)
        
        menu.addSeparator()
        
        # Filtering toggle
        self.filter_action = QAction("Enable Filtering", self)
        self.filter_action.setCheckable(True)
        self.filter_action.setChecked(self.config.get('filtering.enabled', False))
        self.filter_action.triggered.connect(self.on_filter_toggle)
        menu.addAction(self.filter_action)
        
        menu.addSeparator()
        
        # Exit action
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(lambda: self.exit_signal.emit())
        menu.addAction(exit_action)
        
        self.setContextMenu(menu)
    
    def on_activated(self, reason):
        """Handle tray icon activation"""
        if reason == QSystemTrayIcon.DoubleClick:
            self.show_dashboard_signal.emit()
    
    def on_filter_toggle(self, checked: bool):
        """Handle filter toggle from tray menu"""
        self.toggle_filtering_signal.emit(checked)
        self.update_filter_status(checked)
    
    def update_filter_status(self, enabled: bool):
        """Update filter action text"""
        self.filter_action.setText("Disable Filtering" if enabled else "Enable Filtering")
        self.filter_action.setChecked(enabled)
    
    def show_notification(self, title: str, message: str, 
                         icon: QSystemTrayIcon.MessageIcon = QSystemTrayIcon.Information):
        """Show tray notification"""
        self.showMessage(title, message, icon, 3000)  # 3 seconds
