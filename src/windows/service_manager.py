"""
Windows Service Manager
Handles installation and management of Defensiq as a Windows service
IMPORTANT: Requires pywin32 and administrator privileges
"""

import sys
import os
from pathlib import Path

try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
    PYWIN32_AVAILABLE = True
except ImportError:
    PYWIN32_AVAILABLE = False
    print("[WARNING] pywin32 not available. Service installation will not work.")

from core.logger import get_logger, EventType


if PYWIN32_AVAILABLE:
    class DefensiqService(win32serviceutil.ServiceFramework):
        """Windows Service for Defensiq Network Security"""
        
        _svc_name_ = "DefensiqNetworkSecurity"
        _svc_display_name_ = "Defensiq Network Security"
        _svc_description_ = "Ethical network monitoring and security service"
        
        def __init__(self, args):
            """Initialize service"""
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.stop_event = win32event.CreateEvent(None, 0, 0, None)
            self.running = True
        
        def SvcStop(self):
            """Stop the service"""
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self.stop_event)
            self.running = False
        
        def SvcDoRun(self):
            """Run the service"""
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, '')
            )
            
            self.main()
        
        def main(self):
            """Main service loop"""
            from network.filter_engine import run_service
            
            # Log service start
            logger = get_logger()
            logger.log_event(
                EventType.SERVICE_STARTED,
                "Defensiq service started",
                {}
            )
            
            try:
                # Run the service
                # Note: This is a simplified version - production would need
                # more sophisticated service loop with stop event checking
                run_service(debug=False)
            
            except Exception as e:
                logger.log_event(
                    EventType.ERROR_OCCURRED,
                    f"Service error: {e}",
                    {'exception': str(e)}
                )


def install_service():
    """Install Defensiq as a Windows service"""
    if not PYWIN32_AVAILABLE:
        print("[ERROR] pywin32 not available. Cannot install service.")
        print("[INFO] Install with: pip install pywin32")
        return False
    
    try:
        # Get Python executable and script path
        python_exe = sys.executable
        script_path = Path(__file__).parent.parent.parent / "main.py"
        
        print(f"[INFO] Installing Defensiq Network Security service...")
        print(f"[INFO] Python: {python_exe}")
        print(f"[INFO] Script: {script_path}")
        
        # Install service
        win32serviceutil.InstallService(
            DefensiqService._servicemanager_class_,
            DefensiqService._svc_name_,
            DefensiqService._svc_display_name_,
            startType=win32service.SERVICE_AUTO_START,
            description=DefensiqService._svc_description_
        )
        
        print("[SUCCESS] Service installed successfully!")
        print(f"[INFO] Service name: {DefensiqService._svc_name_}")
        print("[INFO] You can start the service with:")
        print(f"       net start {DefensiqService._svc_name_}")
        
        return True
    
    except Exception as e:
        print(f"[ERROR] Failed to install service: {e}")
        print("[INFO] Make sure you are running as Administrator")
        return False


def uninstall_service():
    """Uninstall Defensiq Windows service"""
    if not PYWIN32_AVAILABLE:
        print("[ERROR] pywin32 not available. Cannot uninstall service.")
        return False
    
    try:
        print(f"[INFO] Uninstalling {DefensiqService._svc_display_name_}...")
        
        # Stop service if running
        try:
            win32serviceutil.StopService(DefensiqService._svc_name_)
            print("[INFO] Service stopped")
        except:
            pass
        
        # Remove service
        win32serviceutil.RemoveService(DefensiqService._svc_name_)
        
        print("[SUCCESS] Service uninstalled successfully!")
        
        return True
    
    except Exception as e:
        print(f"[ERROR] Failed to uninstall service: {e}")
        return False


def start_service():
    """Start Defensiq service"""
    if not PYWIN32_AVAILABLE:
        print("[ERROR] pywin32 not available.")
        return False
    
    try:
        win32serviceutil.StartService(DefensiqService._svc_name_)
        print(f"[SUCCESS] Service {DefensiqService._svc_name_} started")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to start service: {e}")
        return False


def stop_service():
    """Stop Defensiq service"""
    if not PYWIN32_AVAILABLE:
        print("[ERROR] pywin32 not available.")
        return False
    
    try:
        win32serviceutil.StopService(DefensiqService._svc_name_)
        print(f"[SUCCESS] Service {DefensiqService._svc_name_} stopped")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to stop service: {e}")
        return False


def get_service_status() -> dict:
    """Get service status"""
    if not PYWIN32_AVAILABLE:
        return {'error': 'pywin32 not available'}
    
    try:
        status = win32serviceutil.QueryServiceStatus(DefensiqService._svc_name_)
        
        status_map = {
            win32service.SERVICE_STOPPED: 'STOPPED',
            win32service.SERVICE_START_PENDING: 'STARTING',
            win32service.SERVICE_STOP_PENDING: 'STOPPING',
            win32service.SERVICE_RUNNING: 'RUNNING',
            win32service.SERVICE_CONTINUE_PENDING: 'CONTINUING',
            win32service.SERVICE_PAUSE_PENDING: 'PAUSING',
            win32service.SERVICE_PAUSED: 'PAUSED'
        }
        
        return {
            'status': status_map.get(status[1], 'UNKNOWN'),
            'status_code': status[1]
        }
    
    except Exception as e:
        return {'error': str(e)}
