#!/usr/bin/env python3
"""
Test script to debug import issues with the tools package
"""

import sys
import os

print("🔍 Testing imports for XKRed27 Security Suite")
print("=" * 50)

# Check current working directory
print(f"Current working directory: {os.getcwd()}")

# Check if tools directory exists
tools_dir = "tools"
if os.path.exists(tools_dir):
    print(f"✅ Tools directory found: {tools_dir}")
    
    # List contents
    print(f"📁 Contents of {tools_dir}:")
    for item in os.listdir(tools_dir):
        item_path = os.path.join(tools_dir, item)
        if os.path.isfile(item_path):
            print(f"   📄 {item}")
        elif os.path.isdir(item_path):
            print(f"   📁 {item}/")
else:
    print(f"❌ Tools directory not found: {tools_dir}")

# Check Python path
print(f"\n🐍 Python path:")
for i, path in enumerate(sys.path):
    print(f"   {i}: {path}")

# Try importing tools package
print(f"\n📦 Testing tools package import:")
try:
    import tools
    print(f"✅ Successfully imported tools package")
    print(f"   Package location: {tools.__file__}")
    
    # Try to list contents
    try:
        print(f"   Package contents: {dir(tools)}")
    except Exception as e:
        print(f"   Could not list contents: {e}")
        
except ImportError as e:
    print(f"❌ Failed to import tools package: {e}")

# Try importing individual modules
print(f"\n🔧 Testing individual module imports:")
modules_to_test = [
    "network_scanner",
    "nmap_scanner", 
    "medusa_brute",
    "nikto_scanner",
    "hydra_scanner",
    "gobuster_scanner",
    "anon_surfer"
]

for module_name in modules_to_test:
    try:
        # Try package import first
        module = __import__(f"tools.{module_name}", fromlist=[module_name])
        print(f"✅ {module_name}: {module}")
    except ImportError as e1:
        try:
            # Try direct import
            module = __import__(module_name)
            print(f"✅ {module_name}: {module} (direct)")
        except ImportError as e2:
            print(f"❌ {module_name}: Package import failed: {e1}")
            print(f"   Direct import failed: {e2}")

print(f"\n🏁 Import test complete!")
