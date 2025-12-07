"""
Defensiq Network Security - Main Entry Point
Ethical Windows Network Security Application

Author: Defensiq Team
Version: 1.0.0
"""

import sys
import argparse
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

def main():
    """Main entry point for the application"""
    parser = argparse.ArgumentParser(
        description='Defensiq Network Security - Ethical Network Monitoring & Protection'
    )
    parser.add_argument(
        '--mode',
        choices=['gui', 'service', 'install-service', 'uninstall-service'],
        default='gui',
        help='Operation mode: gui (default), service, install-service, uninstall-service'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )
    
    args = parser.parse_args()
    
    if args.mode == 'gui':
        # Launch GUI
        from gui.dashboard import launch_gui
        launch_gui(debug=args.debug)
    
    elif args.mode == 'service':
        # Run as background service
        from network.filter_engine import run_service
        run_service(debug=args.debug)
    
    elif args.mode == 'install-service':
        # Install Windows service
        from windows.service_manager import install_service
        install_service()
    
    elif args.mode == 'uninstall-service':
        # Uninstall Windows service
        from windows.service_manager import uninstall_service
        uninstall_service()

if __name__ == '__main__':
    main()
