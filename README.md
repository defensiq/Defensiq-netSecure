<img width="1907" height="1002" alt="image" src="https://github.com/user-attachments/assets/d652e06c-ed00-4bf9-b6b8-5301b58692ac" /># Defensiq Network Security

<div align="center">

<img src="https://github.com/defensiq/Defensiq-netSecure/blob/main/logs/Defesniq.logo%20(1)%20(1).png" alt="Defensiq Logo" width="25%">


**Ethical Windows Network Security & Monitoring Application**

[![Windows](https://img.shields.io/badge/Platform-Windows%2010%2F11-blue?logo=windows)](https://www.microsoft.com/windows)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://www.python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![GUI](https://img.shields.io/badge/GUI-PySide6-brightgreen)](https://doc.qt.io/qtforpython/)

*Real-time network monitoring, traffic filtering, and application control for Windows*

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Screenshots](#screenshots) • [Development](#development)

</div>

---

## 🌟 Features

### Core Capabilities
- **📊 Real-Time Network Monitoring**: Live traffic statistics, bandwidth tracking, and connection monitoring
- **🛡️ Domain & IP Blocking**: Import and manage blocklists (JSON/TXT formats)
- **🎯 Application Controls**: Per-application network blocking and management
- **🔒 DNS-over-HTTPS (DoH)**: Encrypted DNS with multiple provider support (Cloudflare, Quad9, Google, AdGuard)
- **☁️ NextDNS Integration**: Cloud-based blocklists and threat intelligence
- **🔧 Network Diagnostics**: Automated health checks and repair tools
- **📈 Advanced Visualization**: Matplotlib-powered charts and real-time graphs
- **💾 Comprehensive Logging**: CSV/JSON/TXT export capabilities

### Security Features
- Real-time packet filtering
- Traffic analysis by protocol
- Blocked vs allowed traffic monitoring
- Network connection tracking
- Process-level network control

---

## 📋 Requirements

### System Requirements
- **OS**: Windows 10 or Windows 11
- **Privileges**: Administrator rights required
- **Memory**: 4GB RAM minimum
- **Disk**: 500MB free space

### Dependencies (Included in Executable)
- Python 3.8+
- PySide6 (Qt GUI framework)
- PyDivert (packet filtering) *
- psutil (process monitoring)
- matplotlib (charts & graphs)
- dnspython (DNS operations)

> **⚠️ Important**: PyDivert requires the [WinDivert driver](https://reqrypt.org/windivert.html) to be installed separately.

---

## 💿 Installation

### Option 1: Download Pre-built Executable (Recommended)

1. **Download** the latest release from [Releases]([https://github.com/yourusername/defensiq/releases](https://github.com/defensiq/Defensiq-netSecure/blob/main/dist/Defensiq-Release/Defensiq.exe))
2. **Extract** the ZIP file to your desired location
3. **Install WinDivert** driver:
   - Download from [https://reqrypt.org/windivert.html](https://reqrypt.org/windivert.html)
   - Extract and run `install.bat` as Administrator
4. **Run** `Defensiq.exe` as Administrator

### Option 2: Run from Source

```bash
# Clone the repository
git clone [https://github.com/yourusername/defensiq.git](https://github.com/defensiq/Defensiq-netSecure.git)
cd defensiq

# Install dependencies
pip install -r requirements.txt

# Install PyDivert driver (Administrator required)
# Download from https://reqrypt.org/windivert.html

# Run the application
python main.py
```

### Option 3: Build Your Own Executable

```bash
# Install PyInstaller
pip install pyinstaller

# Build
build.bat

# Exe will be in dist/Defensiq-Release/
```

---

## 🚀 Usage

### First Launch

1. **Right-click** `Defensiq.exe` → **Run as administrator**
2. The dashboard will open automatically
3. Monitoring starts immediately in **passive mode**

### Dashboard Overview

The main interface consists of 8 tabs:

#### 1. **Dashboard** 📊
- Real-time network statistics (packets sent/received, active connections)
- Bandwidth and connection trend graphs
- Traffic analysis pie charts (protocol distribution, allowed vs blocked)

#### 2. **Traffic Monitor** 🔍
- Live connection table with local/remote addresses
- Process identification
- Connection status tracking

#### 3. **Blocklist** 🚫
- Add/remove domains and IPs
- Import blocklists from files
- Export current rules
- Statistics display

#### 4. **App Controls** 🎯
- View running processes with network activity
- Block or allow specific applications
- Manage application rules
- Auto-refresh every 3 seconds

#### 5. **DNS & NextDNS** 🔒
- Configure DNS-over-HTTPS providers
- NextDNS profile integration
- Fetch cloud blocklists
- Test DNS connections

#### 6. **Diagnostics** 🔧
- Run full network health check
- Internet connectivity test
- DNS resolution test
- Firewall status check
- Network adapter verification
- Automated repair tools

#### 7. **Logs & Reports** 📝
- View recent security events
- Export logs (CSV/JSON/TXT)
- Search and filter events

#### 8. **Settings** ⚙️
- Theme selection (Light/Dark)
- Monitoring preferences
- DoS detection threshold
- Auto-save configuration

### Enabling Packet Filtering

1. Click the **Filtering** toggle in the header (OFF → ON)
2. If prompted, confirm administrator access
3. Status will show "🛡️ Filtering Active" when running

> **Note**: Filtering requires administrator privileges and WinDivert driver

---

## 📸 Screenshots

<details>
<summary>Click to expand screenshots</summary>

### Dashboard
![Dashboard](<img width="1907" height="1002" alt="image" src="https://github.com/user-attachments/assets/3d89fde2-abe8-4a7f-ae63-91366975bc2d" />
)

### Application Controls
![App Controls](<img width="1897" height="947" alt="image" src="https://github.com/user-attachments/assets/98c3f7ff-1ec6-498e-a625-df766edf077a" />
)

### Network Diagnostics
![Diagnostics](<img width="1890" height="811" alt="image" src="https://github.com/user-attachments/assets/ec304460-d8ee-4181-889b-cfa71b10c11d" />
)

</details>

---

## ⚙️ Configuration

Configuration files are stored in `config/defensiq_config.json`

```json
{
  "app": {
    "theme": "light"
  },
  "filtering": {
    "enabled": false
  },
  "monitoring": {
    "log_all_traffic": false
  },
  "dns": {
    "provider": "cloudflare",
    "enabled": false
  }
}
```

Logs are saved in `logs/` directory with automatic rotation.

---

## 🛠️ Development

### Project Structure

```
Defensiq Network Security/
├── main.py                 # Application entry point
├── requirements.txt        # Python dependencies
├── defensiq.spec          # PyInstaller configuration
├── build.bat              # Build script
├── src/
│   ├── core/              # Core infrastructure
│   │   ├── config.py      # Configuration manager
│   │   └── logger.py      # Logging system
│   ├── network/           # Network operations
│   │   ├── monitor.py     # Traffic monitoring
│   │   ├── filter_engine.py  # Packet filtering
│   │   ├── app_control.py    # Application controls
│   │   ├── doh_resolver.py   # DNS-over-HTTPS
│   │   └── nextdns_client.py # NextDNS integration
│   ├── rules/             # Rule management
│   │   └── blocklist_manager.py
│   ├── security/          # Security features
│   │   └── cia_monitor.py
│   ├── utils/             # Utilities
│   │   └── diagnostics.py
│   └── gui/               # User interface
│       ├── dashboard.py   # Main window
│       ├── widgets.py     # Custom widgets
│       ├── app_control_tab.py
│       ├── dns_tab.py
│       └── diagnostics_tab.py
└── assets/                # Icons and images
```

### Setting Up Development Environment

```bash
# Create virtual environment
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run in development mode
python main.py
```

### Building from Source

```bash
# Install build tools
pip install pyinstaller

# Run build script
build.bat

# Or manually
pyinstaller defensiq.spec --clean
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

**This application is for ETHICAL and EDUCATIONAL purposes only.**

- Only use on networks you own or have permission to monitor
- Comply with all local laws and regulations
- The authors are not responsible for misuse
- Not intended for unauthorized network monitoring or malicious activities

---

## 🐛 Known Issues

- **PyDivert Driver**: Must be installed separately for filtering features
- **Administrator Rights**: Required for packet filtering operations
- **Antivirus Warnings**: May flag due to network operations (add to whitelist)
- **First Run**: May take a few seconds to initialize on first launch

---

## 🔜 Roadmap

- [ ] Auto-update blocklists
- [ ] Application password lock
- [ ] Enhanced PDF reporting
- [ ] Bandwidth limits per process
- [ ] HTTPS certificate validation
- [ ] Email alerts
- [ ] Custom themes

---

## 📚 Resources

- [PyDivert Documentation](https://github.com/ffalcinelli/pydivert)
- [PySide6 Documentation](https://doc.qt.io/qtforpython/)
- [NextDNS API](https://nextdns.io/api)
- [DNS-over-HTTPS RFC](https://datatracker.ietf.org/doc/html/rfc8484)

---

## 💬 Support

Found a bug? Have a feature request?

- 🐛 [Open an issue](https://github.com/defensiq/Defensiq-netSecure/tree/main)
- 💡 [Discussions]([https://github.com/yourusername/defensiq/discussions](https://github.com/defensiq/Defensiq-netSecure/tree/main))

---

<div align="center">

**Made with ❤️ for ethical network security**

[⬆ Back to top](#defensiq-network-security)

</div>
