#!/usr/bin/env python3
"""
Test script for sudo functionality in Nmap UI
This script tests the sudo authentication mechanism
"""

import subprocess
import getpass
import sys

def test_sudo_with_password():
    """Test sudo authentication with password"""
    print("🔐 Testing sudo authentication mechanism")
    print("=" * 50)
    
    try:
        # Get password securely
        password = getpass.getpass("Enter your password to test sudo: ")
        
        if not password:
            print("❌ No password provided")
            return False
        
        # Test command - simple whoami with sudo
        cmd = ['sudo', '-S', 'whoami']
        
        print(f"Testing command: {' '.join(cmd)}")
        
        # Run the command
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Send password with proper error handling
        try:
            stdout, stderr = process.communicate(input=password + '\n', timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            print("❌ Command timed out")
            return False
        
        if process.returncode == 0:
            print("✅ Sudo authentication successful!")
            print(f"Running as: {stdout.strip()}")
            
            # Test with nmap
            print("\n🔍 Testing nmap with sudo...")
            nmap_cmd = ['sudo', '-S', 'nmap', '-sS', '-p', '80', '127.0.0.1']
            
            nmap_process = subprocess.Popen(
                nmap_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            try:
                nmap_stdout, nmap_stderr = nmap_process.communicate(input=password + '\n', timeout=60)
            except subprocess.TimeoutExpired:
                nmap_process.kill()
                print("❌ Nmap command timed out")
                return False
            
            if nmap_process.returncode == 0:
                print("✅ Nmap sudo execution successful!")
                print("Preview of nmap output:")
                print("-" * 30)
                print(nmap_stdout[:200] + "..." if len(nmap_stdout) > 200 else nmap_stdout)
                print("-" * 30)
                return True
            else:
                print("❌ Nmap sudo execution failed")
                print(f"Error: {nmap_stderr}")
                return False
                
        else:
            print("❌ Sudo authentication failed")
            if "incorrect password" in stderr.lower() or "sorry, try again" in stderr.lower():
                print("Reason: Incorrect password")
            elif "not in the sudoers file" in stderr.lower():
                print("Reason: User not in sudoers file")
            else:
                print(f"Reason: {stderr}")
            return False
            
    except KeyboardInterrupt:
        print("\n❌ Test cancelled by user")
        return False
    except Exception as e:
        print(f"❌ Test error: {e}")
        return False
    finally:
        # Clear password from memory
        password = None

def main():
    """Main test function"""
    print("🚀 Nmap UI Sudo Authentication Test")
    print("This test verifies that sudo authentication works correctly")
    print("for the Nmap UI application.\n")
    
    # Check if sudo is available
    try:
        result = subprocess.run(['which', 'sudo'], capture_output=True)
        if result.returncode != 0:
            print("❌ sudo command not found on this system")
            print("This feature requires sudo to be installed")
            return
    except:
        print("❌ Unable to check for sudo availability")
        return
    
    # Check if nmap is available
    try:
        result = subprocess.run(['which', 'nmap'], capture_output=True)
        if result.returncode != 0:
            print("❌ nmap command not found")
            print("Please install nmap first")
            return
    except:
        print("❌ Unable to check for nmap availability")
        return
    
    print("✅ Prerequisites check passed\n")
    
    # Run the test
    success = test_sudo_with_password()
    
    print("\n" + "=" * 50)
    if success:
        print("✅ All tests passed!")
        print("The sudo authentication feature should work in the Nmap UI.")
    else:
        print("❌ Tests failed!")
        print("You may need to use the fallback TCP Connect scan option.")
    
    print("\nTo use sudo authentication in the Nmap UI:")
    print("1. Select a privileged scan type (SYN, UDP, etc.)")
    print("2. Check 'Use sudo authentication' in the sidebar")
    print("3. Enter your password in the secure field")
    print("4. Run the scan")

if __name__ == "__main__":
    main()
