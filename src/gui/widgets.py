"""
Custom GUI Widgets for Defensiq
Includes status indicators, stat cards, charts, and toggle switches
"""

from PySide6.QtWidgets import QWidget, QLabel, QPushButton, QVBoxLayout, QHBoxLayout, QFrame
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QPainter, QPen
from typing import List


class StatusCircle(QWidget):
    """Custom widget that draws a colored circle"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.color = QColor(100, 100, 100)  # Default gray
        self.setFixedSize(16, 16)
    
    def set_color(self, color: QColor):
        """Set the circle color"""
        self.color = color
        self.update()
    
    def paintEvent(self, event):
        """Paint the circle"""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Draw circle
        painter.setBrush(self.color)
        painter.setPen(QPen(Qt.NoPen))
        painter.drawEllipse(2, 2, 12, 12)


class StatusIndicator(QWidget):
    """Colored status indicator with label"""
    
    def __init__(self, label: str, parent=None):
        super().__init__(parent)
        self.label_text = label
        
        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Status circle
        self.circle_widget = StatusCircle()
        
        # Label
        self.label = QLabel(label)
        
        layout.addWidget(self.circle_widget)
        layout.addWidget(self.label)
        layout.addStretch()
        
        self.setLayout(layout)
    
    def set_status(self, status: str):
        """Set status and update color"""
        status_colors = {
            'SECURE': QColor(46, 204, 113),  # Green
            'NORMAL': QColor(46, 204, 113),
            'INTACT': QColor(46, 204, 113),
            'AT_RISK': QColor(241, 196, 15),  # Yellow
            'DEGRADED': QColor(241, 196, 15),
            'WARNING': QColor(241, 196, 15),
            'COMPROMISED': QColor(231, 76, 60),  # Red
            'CRITICAL': QColor(231, 76, 60),
            'DISABLED': QColor(149, 165, 166)  # Gray
        }
        
        color = status_colors.get(status, QColor(100, 100, 100))
        self.circle_widget.set_color(color)


class StatCard(QFrame):
    """Card displaying a statistic"""
    
    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self.setFrameStyle(QFrame.StyledPanel | QFrame.Raised)
        self.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #ffffff, stop:1 #f0f3f5);
                border: 1px solid #d5d8dc;
                border-radius: 10px;
                padding: 15px;
            }
            QFrame:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #f8f9fa, stop:1 #e9ecef);
                border: 2px solid #3498db;
            }
        """)
        
        layout = QVBoxLayout()
        
        # Title
        self.title_label = QLabel(title)
        self.title_label.setStyleSheet("""
            font-weight: bold; 
            font-size: 11pt;
            color: #34495e;
        """)
        
        # Value
        self.value_label = QLabel("--")
        self.value_label.setStyleSheet("""
            font-size: 28pt;
            font-weight: bold;
            color: #2980b9;
        """)
        self.value_label.setAlignment(Qt.AlignCenter)
        
        # Subtitle (optional)
        self.subtitle_label = QLabel("")
        self.subtitle_label.setStyleSheet("""
            font-size: 9pt;
            color: #7f8c8d;
        """)
        self.subtitle_label.setAlignment(Qt.AlignCenter)
        
        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)
        layout.addWidget(self.subtitle_label)
        layout.addStretch()
        
        self.setLayout(layout)
    
    def set_value(self, value: str, subtitle: str = ""):
        """Update displayed value"""
        self.value_label.setText(value)
        self.subtitle_label.setText(subtitle)


class SimpleChart(QFrame):
    """Matplotlib-based chart widget for better visualization"""
    
    def __init__(self, title: str, max_data_points: int = 60, parent=None):
        super().__init__(parent)
        # Remove emojis from title for matplotlib (causes glyph warnings)
        self.title = ''.join(char for char in title if ord(char) < 128) or title
        self.display_title = title  # Keep original for widget
        self.max_data_points = max_data_points
        self.data_points = []
        
        self.setFrameStyle(QFrame.StyledPanel | QFrame.Raised)
        self.setStyleSheet("""
            QFrame {
                background: white;
                border: 1px solid #bdc3c7;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        
        # Create matplotlib figure with better sizing
        from matplotlib.figure import Figure
        from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg
        
        self.figure = Figure(figsize=(6, 3), dpi=80, facecolor='#f8f9fa')
        self.canvas = FigureCanvasQTAgg(self.figure)
        self.ax = self.figure.add_subplot(111)
        
        # Style the plot
        self.ax.set_facecolor('#ffffff')
        self.ax.grid(True, alpha=0.3, linestyle='--', linewidth=0.5)
        
        # Layout
        layout = QVBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)
        layout.addWidget(self.canvas)
        self.setLayout(layout)
        
        # Initialize empty plot
        self.update_plot()
    
    def add_data_point(self, value: float):
        """Add a data point to the chart"""
        self.data_points.append(value)
        
        # Keep only max_data_points
        if len(self.data_points) > self.max_data_points:
            self.data_points = self.data_points[-self.max_data_points:]
        
        self.update_plot()
    
    def update_plot(self):
        """Update the matplotlib plot"""
        self.ax.clear()
        
        if len(self.data_points) > 0:
            x = list(range(len(self.data_points)))
            
            # Plot line
            self.ax.plot(x, self.data_points, 
                        color='#3498db', 
                        linewidth=2.5, 
                        marker='o', 
                        markersize=3,
                        markerfacecolor='#2980b9',
                        markeredgecolor='white',
                        markeredgewidth=1)
            
            # Fill area under curve
            self.ax.fill_between(x, self.data_points, alpha=0.3, color='#3498db')
            
            # Set limits with padding
            max_val = max(self.data_points) if self.data_points else 1
            self.ax.set_ylim(0, max_val * 1.2)
            
        else:
            # Empty state
            self.ax.text(0.5, 0.5, 'No data yet', 
                        ha='center', va='center',
                        transform=self.ax.transAxes,
                        fontsize=10, color='#95a5a6')
        
        # Style - use ASCII-only title
        self.ax.set_facecolor('#ffffff')
        self.ax.grid(True, alpha=0.3, linestyle='--', linewidth=0.5)
        self.ax.set_title(self.title, fontsize=10, fontweight='bold', pad=8)
        self.ax.set_xlabel('Time', fontsize=8, color='#7f8c8d')
        self.ax.set_ylabel('Value', fontsize=8, color='#7f8c8d')
        
        # Remove x-axis labels for cleaner look
        self.ax.set_xticks([])
        
        # Style spines
        for spine in self.ax.spines.values():
            spine.set_color('#d5d8dc')
            spine.set_linewidth(1)
        
        # Use tight_layout with error handling
        try:
            self.figure.tight_layout(pad=0.5)
        except:
            pass  # Ignore tight_layout warnings
        
        self.canvas.draw()
    
    def clear(self):
        """Clear all data"""
        self.data_points = []
        self.update_plot()


class PieChart(QFrame):
    """Pie chart widget using matplotlib"""
    
    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        # Remove emojis from title for matplotlib
        self.title = ''.join(char for char in title if ord(char) < 128) or title
        self.display_title = title
        
        self.setFrameStyle(QFrame.StyledPanel | QFrame.Raised)
        self.setStyleSheet("""
            QFrame {
                background: white;
                border: 1px solid #bdc3c7;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        
        # Create matplotlib figure
        from matplotlib.figure import Figure
        from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg
        
        self.figure = Figure(figsize=(4, 3), dpi=80, facecolor='#f8f9fa')
        self.canvas = FigureCanvasQTAgg(self.figure)
        self.ax = self.figure.add_subplot(111)
        
        # Layout
        layout = QVBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)
        layout.addWidget(self.canvas)
        self.setLayout(layout)
        
        # Initialize empty
        self.update_chart({})
    
    def update_chart(self, data: dict):
        """Update pie chart with data dict {label: value}"""
        self.ax.clear()
        
        if data and sum(data.values()) > 0:
            labels = list(data.keys())
            sizes = list(data.values())
            colors = ['#3498db', '#e74c3c', '#2ecc71', '#f39c12', '#9b59b6', '#1abc9c']
            
            # Create pie chart
            wedges, texts, autotexts = self.ax.pie(
                sizes, 
                labels=labels,
                colors=colors[:len(labels)],
                autopct='%1.1f%%',
                startangle=90,
                textprops={'fontsize': 9}
            )
            
            # Enhance text
            for autotext in autotexts:
                autotext.set_color('white')
                autotext.set_fontweight('bold')
            
        else:
            self.ax.text(0.5, 0.5, 'No data', 
                        ha='center', va='center',
                        transform=self.ax.transAxes,
                        fontsize=10, color='#95a5a6')
        
        # Use ASCII-only title
        self.ax.set_title(self.title, fontsize=10, fontweight='bold', pad=8)
        
        # Use tight_layout with error handling
        try:
            self.figure.tight_layout(pad=0.5)
        except:
            pass  # Ignore tight_layout warnings
        
        self.canvas.draw()


class ToggleSwitch(QPushButton):
    """Custom toggle switch widget with ON/OFF labels"""
    
    toggled = Signal(bool)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setCheckable(True)
        self.setMinimumWidth(120)
        self.setMinimumHeight(40)
        self.setCursor(Qt.PointingHandCursor)
        self.update_style()
        
        # Connect to update style on toggle
        self.toggled.connect(self.update_style)
    
    def update_style(self):
        """Update button style based on state"""
        if self.isChecked():
            # ON state - Green
            self.setText("ON")
            self.setStyleSheet("""
                QPushButton {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                        stop:0 #27ae60, stop:1 #2ecc71);
                    color: white;
                    border: 2px solid #1e8449;
                    border-radius: 20px;
                    font-weight: bold;
                    font-size: 12pt;
                    padding: 5px 15px;
                }
                QPushButton:hover {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                        stop:0 #229954, stop:1 #27ae60);
                }
                QPushButton:pressed {
                    background: #1e8449;
                }
            """)
        else:
            # OFF state - Red
            self.setText("OFF")
            self.setStyleSheet("""
                QPushButton {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                        stop:0 #95a5a6, stop:1 #7f8c8d);
                    color: white;
                    border: 2px solid #5d6d7e;
                    border-radius: 20px;
                    font-weight: bold;
                    font-size: 12pt;
                    padding: 5px 15px;
                }
                QPushButton:hover {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                        stop:0 #7f8c8d, stop:1 #626567);
                }
                QPushButton:pressed {
                    background: #5d6d7e;
                }
            """)
