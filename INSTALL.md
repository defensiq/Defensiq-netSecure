# Installation Guide - Defensiq Network Security

## Prerequisites

### 1. System Requirements
- Windows 10 or Windows 11 (64-bit)
- At least 4GB RAM
- 500MB free disk space
- Administrator account access

### 2. Python Installation

**Download Python 3.9 or later:**
1. Visit https://www.python.org/downloads/
2. Download Python 3.9+ for Windows
3. Run the installer
4. ✅ **IMPORTANT**: Check "Add Python to PATH"
5. Click "Install Now"

**Verify Python installation:**
```bash
python --version
# Should show: Python 3.9.x or higher
```

## Installation Steps

### Step 1: Navigate to Project Directory

Open PowerShell or Command Prompt:
```bash
cd "E:\Coding projects\Defensiq Network security"
```

### Step 2: Create Virtual Environment (Recommended)

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
.\venv\Scripts\activate

# You should see (venv) in your prompt
```

### Step 3: Install Dependencies

```bash
# Upgrade pip first
python -m pip install --upgrade pip

# Install all required packages
pip install -r requirements.txt
```

**Expected output:**
```
Successfully installed PySide6-6.7.0 pydivert-2.1.0 psutil-5.9.8 pywin32-306 ...
```

### Step 4: Post-Installation Configuration

**For pywin32:**
```bash
# Run post-install script (required for service functionality)
python -m pywin32_postinstall -install
```

### Step 5: Verify Installation

```bash
# Test basic import
python -c "import PySide6, pydivert, psutil; print('All imports successful!')"
```

If successful, you should see:
```
All imports successful!
```

## First Run

### Method 1: GUI Mode (Recommended for First-Time Users)

```bash
# Run as Administrator (Right-click PowerShell -> "Run as Administrator")
cd "E:\Coding projects\Defensiq Network security"
.\venv\Scripts\activate  # If using virtual environment
python main.py --mode gui
```

The GUI should launch. You'll see:
1. Main Dashboard with CIA Triad indicators
2. All filtering is **disabled by default**
3. System tray icon appears

### Method 2: Service Mode (Advanced)

```bash
# Install as Windows Service (Run as Administrator)
python main.py --mode install-service

# Start the service
net start DefensiqNetworkSecurity

# Check service status
sc query DefensiqNetworkSecurity
```

## Configuration

### Initial Configuration

On first run, Defensiq creates default configuration files:
- `config/settings.json` - Application settings
- `config/blocklist.json` - Empty blocklist
- `logs/` directory - Log files

### Enable Packet Filtering

**⚠️ IMPORTANT**: Filtering is **opt-in** and requires admin privileges.

**Via GUI:**
1. Launch application as Administrator
2. Click the "Filtering" toggle in the header
3. Confirm the UAC prompt
4. Status will show "ON" when active

**Via Configuration File:**
Edit `config/settings.json`:
```json
{
  "filtering": {
    "enabled": true  // Change to true
  }
}
```

### Import Blocklist

**Using GUI:**
1. Open "Blocklist" tab
2. Click "Import List"
3. Select `config/example_blocklist.json` or your own list
4. Click "Open"

**Manually:**
Copy your blocklist to `config/blocklist.json`

## Troubleshooting Installation Issues

### Issue: "pip: command not found"

**Solution:**
```bash
# Use python -m pip instead
python -m pip install -r requirements.txt
```

### Issue: "Microsoft Visual C++ 14.0 is required"

**Solution:**
1. Download "Microsoft C++ Build Tools" from:
   https://visualstudio.microsoft.com/visual-cpp-build-tools/
2. Install with "Desktop development with C++" workload
3. Restart and retry `pip install`

### Issue: "Access is denied" during pywin32 post-install

**Solution:**
```bash
# Run PowerShell as Administrator
python -m pywin32_postinstall -install
```

### Issue: "WinDivert driver failed to load"

**Possible causes:**
1. Not running as Administrator
2. Antivirus blocking the driver
3. Secure Boot enabled (rare)

**Solution:**
```bash
# Run PowerShell as Administrator
# Temporarily disable antivirus
# Try again
python main.py --mode gui
```

### Issue: GUI doesn't appear

**Solution:**
```bash
# Check for errors
python main.py --mode gui --debug

# Reinstall PySide6
pip uninstall PySide6
pip install PySide6==6.7.0
```

## Updating

To update Defensiq to a new version:

```bash
cd "E:\Coding projects\Defensiq Network security"

# Pull updates (if using git)
git pull

# Update dependencies
.\venv\Scripts\activate
pip install --upgrade -r requirements.txt

# If service is installed, restart it
net stop DefensiqNetworkSecurity
net start DefensiqNetworkSecurity
```

## Uninstallation

### Remove Service (if installed)

```bash
# Run as Administrator
python main.py --mode uninstall-service
# or
sc delete DefensiqNetworkSecurity
```

### Remove Application

```bash
# Deactivate virtual environment (if active)
deactivate

# Delete project folder
# IMPORTANT: Back up config/blocklist.json if you want to keep your blocklists
# Then delete the entire folder
```

### Clean Up Python Packages (Optional)

```bash
pip uninstall -r requirements.txt -y
```

## Next Steps

After successful installation:

1. **Read the README.md** for feature overview
2. **Review example blocklists** in `config/`
3. **Launch the GUI** and explore tabs
4. **Import a small blocklist** to test
5. **Enable filtering** when ready (requires admin)
6. **Check logs** in `logs/` directory

## Getting Help

If you encounter issues:

1. **Check logs**: `logs/errors.log`
2. **Enable debug mode**: `python main.py --debug --mode gui`
3. **Verify admin privileges**: Right-click PowerShell -> "Run as Administrator"
4. **Check Windows Event Viewer**: Application logs

## Security Best Practices

✅ **DO:**
- Run as Administrator only when needed
- Review blocklists before importing
- Regularly export your configuration
- Monitor logs for unusual activity

❌ **DON'T:**
- Share your configuration files (may contain sensitive info)
- Import untrusted blocklists
- Disable integrity checks
- Run with filtering enabled 24/7 without testing first

---

**Congratulations! You're ready to use Defensiq Network Security.**

For questions about usage, see the main **README.md**.
