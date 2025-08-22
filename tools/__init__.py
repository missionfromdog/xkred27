# XKRed27 Security Suite - Tools Module
# This file makes the tools directory a Python package

# Import all tool modules to make them available
try:
    from . import network_scanner
    from . import nmap_scanner
    from . import medusa_brute
    from . import nikto_scanner
    from . import hydra_scanner
    from . import gobuster_scanner
    from . import anon_surfer
    from . import system_monitor
except ImportError:
    # If relative imports fail, try absolute imports
    pass

# Define what gets imported with "from tools import *"
__all__ = [
    'network_scanner',
    'nmap_scanner', 
    'medusa_brute',
    'nikto_scanner',
    'hydra_scanner',
    'gobuster_scanner',
    'anon_surfer',
    'system_monitor'
]
