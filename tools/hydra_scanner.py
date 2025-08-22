#!/usr/bin/env python3
"""
Hydra Multi-Protocol Brute Force Scanner Module for Nmap UI Suite
Provides comprehensive brute force capabilities across multiple protocols
"""

import streamlit as st
import subprocess
import json
import pandas as pd
import time
import re
import os
from datetime import datetime
from tools.network_scanner import get_discovered_hosts_for_dropdown, extract_ip_from_selection
from tools.system_monitor import get_global_monitor, create_monitoring_dashboard, get_optimal_thread_count

def validate_ip(ip):
    """Validate IP address format"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(pattern, ip):
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    return False

def validate_hostname(hostname):
    """Validate hostname format"""
    pattern = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, hostname) is not None

def parse_hydra_output(output):
    """Parse Hydra output and structure it for display"""
    lines = output.split('\n')
    results = {
        'target': '',
        'service': '',
        'successful_logins': [],
        'failed_attempts': 0,
        'total_attempts': 0,
        'scan_statistics': {},
        'raw_output': output
    }
    
    for line in lines:
        line = line.strip()
        
        # Extract target and service information
        if 'Hydra' in line and 'starting at' in line:
            # Parse target from Hydra startup line
            match = re.search(r'against (.+?) \(', line)
            if match:
                results['target'] = match.group(1)
        
        # Extract service information
        if '[DATA]' in line and 'attacking' in line:
            match = re.search(r'attacking (.+?):', line)
            if match:
                results['service'] = match.group(1)
        
        # Parse successful logins
        if '[' in line and '] host:' in line and 'login:' in line and 'password:' in line:
            # Extract login details from success line
            # Format: [80][http-get] host: 192.168.1.1   login: admin   password: password
            match = re.search(r'\[(\d+)\]\[(.+?)\]\s+host:\s*(.+?)\s+login:\s*(.+?)\s+password:\s*(.+?)(?:\s|$)', line)
            if match:
                port, service, host, username, password = match.groups()
                success_info = {
                    'host': host.strip(),
                    'port': port.strip(),
                    'service': service.strip(),
                    'username': username.strip(),
                    'password': password.strip(),
                    'full_line': line
                }
                results['successful_logins'].append(success_info)
        
        # Parse statistics
        if '[DATA]' in line:
            if 'max' in line and 'task' in line:
                # Extract max tasks/threads info
                match = re.search(r'max (\d+) tasks', line)
                if match:
                    results['scan_statistics']['max_tasks'] = int(match.group(1))
            
            if 'login try' in line:
                # Extract login attempt counts
                match = re.search(r'(\d+) login tries', line)
                if match:
                    results['total_attempts'] = int(match.group(1))
        
        # Count attempts from progress lines
        if 'attempt' in line.lower() or 'trying' in line.lower():
            results['total_attempts'] += 1
    
    # Calculate failed attempts
    results['failed_attempts'] = results['total_attempts'] - len(results['successful_logins'])
    
    return results

def run_hydra_scan(command, progress_bar, status_text):
    """Run Hydra scan with progress updates and monitoring"""
    try:
        # Get system monitor for performance tracking
        monitor = get_global_monitor()
        
        # Start the process
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            universal_newlines=True
        )
        
        output = ""
        error_output = ""
        attempt_count = 0
        last_monitor_update = time.time()
        
        status_text.text("Starting Hydra brute force scan...")
        progress_bar.progress(0.1)
        
        # Read output line by line
        while True:
            output_line = process.stdout.readline()
            if output_line == '' and process.poll() is not None:
                break
            if output_line:
                output += output_line
                line_lower = output_line.lower()
                
                # Update progress based on scan progress indicators
                if 'trying' in line_lower or 'attempt' in line_lower:
                    attempt_count += 1
                    if attempt_count % 5 == 0:  # Update every 5 attempts
                        progress = min(0.1 + (attempt_count / 100) * 0.8, 0.9)
                        progress_bar.progress(progress)
                        status_text.text(f"Attempting login {attempt_count}...")
                
                # Show successful logins immediately
                if 'host:' in line_lower and 'login:' in line_lower and 'password:' in line_lower:
                    status_text.text(f"✅ Found credentials! {output_line.strip()[:80]}...")
                
                # Show scan statistics
                if '[data]' in line_lower and 'max' in line_lower:
                    status_text.text(f"Scan configured: {output_line.strip()[:60]}...")
                
                # Update monitoring dashboard every 3 seconds during scan
                current_time = time.time()
                if current_time - last_monitor_update > 3.0:
                    try:
                        current_metrics = monitor.get_latest_metrics()
                        if current_metrics:
                            status_text.text(f"Scanning... | CPU: {current_metrics.cpu_percent:.1f}% | Memory: {current_metrics.memory_percent:.1f}% | Attempts: {attempt_count}")
                        last_monitor_update = current_time
                    except:
                        pass
        
        # Get any remaining output
        remaining_output, error_output = process.communicate()
        output += remaining_output
        
        progress_bar.progress(1.0)
        status_text.text("Hydra scan completed!")
        
        return output, error_output, process.returncode
        
    except Exception as e:
        return "", str(e), 1

def create_hydra_html_report(scan_results, scan_command):
    """Create an HTML report of the Hydra scan results"""
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Hydra Brute Force Scan Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .header {{ background-color: #2E86AB; color: white; padding: 20px; border-radius: 5px; }}
            .section {{ margin: 20px 0; padding: 15px; border-radius: 5px; }}
            .success {{ background-color: #e8f5e8; border-left: 4px solid #4caf50; }}
            .info {{ background-color: #e3f2fd; border-left: 4px solid #2196f3; }}
            .summary {{ background-color: #f1f8e9; border-left: 4px solid #4caf50; }}
            .credentials {{ background-color: #fff3e0; border-left: 4px solid #ff9800; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            .command {{ background-color: #f5f5f5; padding: 10px; border-radius: 3px; font-family: monospace; }}
            .success-text {{ color: #2e7d32; font-weight: bold; }}
            .warning-text {{ color: #f57c00; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🔒 Hydra Multi-Protocol Brute Force Report</h1>
            <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="section summary">
            <h2>📊 Scan Summary</h2>
            <p><strong>Target:</strong> {scan_results.get('target', 'N/A')}</p>
            <p><strong>Service:</strong> {scan_results.get('service', 'N/A')}</p>
            <p><strong>Successful Logins:</strong> <span class="success-text">{len(scan_results.get('successful_logins', []))}</span></p>
            <p><strong>Total Attempts:</strong> {scan_results.get('total_attempts', 0)}</p>
            <p><strong>Failed Attempts:</strong> {scan_results.get('failed_attempts', 0)}</p>
        </div>
        
        <div class="section">
            <h2>⚙️ Command Used</h2>
            <div class="command">{scan_command}</div>
        </div>
    """
    
    # Add successful logins section
    if scan_results.get('successful_logins'):
        html_content += """
        <div class="section credentials">
            <h2>🎯 Successful Logins</h2>
            <table>
                <tr>
                    <th>Host</th>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Username</th>
                    <th>Password</th>
                </tr>
        """
        
        for login in scan_results['successful_logins']:
            html_content += f"""
                <tr>
                    <td>{login.get('host', 'N/A')}</td>
                    <td>{login.get('port', 'N/A')}</td>
                    <td>{login.get('service', 'N/A')}</td>
                    <td class="warning-text">{login.get('username', 'N/A')}</td>
                    <td class="warning-text">{login.get('password', 'N/A')}</td>
                </tr>
            """
        
        html_content += "</table></div>"
    else:
        html_content += """
        <div class="section info">
            <h2>🔒 No Successful Logins</h2>
            <p>No valid credentials were found with the provided wordlists and configuration.</p>
        </div>
        """
    
    # Add scan statistics
    if scan_results.get('scan_statistics'):
        html_content += """
        <div class="section info">
            <h2>📈 Scan Statistics</h2>
        """
        for key, value in scan_results['scan_statistics'].items():
            html_content += f"<p><strong>{key.replace('_', ' ').title()}:</strong> {value}</p>"
        html_content += "</div>"
    
    # Add raw output section
    html_content += f"""
        <div class="section">
            <h2>📄 Raw Hydra Output</h2>
            <pre style="background-color: #f5f5f5; padding: 10px; border-radius: 3px; overflow-x: auto;">{scan_results.get('raw_output', '')}</pre>
        </div>
        
        <div class="section">
            <p><em>Report generated by XKRed27 Security Suite - Hydra Scanner</em></p>
        </div>
    </body>
    </html>
    """
    
    return html_content

def show_hydra_interface():
    """Main Hydra brute force interface"""
    st.header("🔒 Hydra Multi-Protocol Brute Force Scanner")
    
    st.info("💡 **Hydra** is a very fast network logon cracker which supports many different services. It's highly flexible and supports dozens of protocols including SSH, FTP, HTTP, SMB, and many more.")
    
    # System Performance Monitoring
    st.markdown("### 📊 System Performance Monitor")
    monitor = get_global_monitor()
    monitoring_container = st.container()
    create_monitoring_dashboard(monitor, monitoring_container)
    
    # Configuration section
    st.subheader("⚙️ Multi-Protocol Brute Force Configuration")
    
    # Create columns for better organization
    col1, col2 = st.columns([2, 1])
    
    with col1:
        # Target specification
        st.markdown("### 🎯 Target Specification")
        
        # Check for discovered hosts
        discovered_hosts = get_discovered_hosts_for_dropdown()
        
        if discovered_hosts:
            st.markdown("#### 📡 Select from Network Discovery")
            selected_host = st.selectbox(
                "Choose a discovered host:",
                options=[""] + discovered_hosts,
                help="Hosts discovered by the Network Discovery scanner. Selection will auto-populate the target field below.",
                key="hydra_host_selectbox"
            )
            
            # Auto-populate target field when selection changes
            if selected_host:
                selected_ip = extract_ip_from_selection(selected_host)
                st.session_state.hydra_target_from_discovery = selected_ip
                st.success(f"✅ Auto-populated target: {selected_ip}")
            
            st.markdown("#### ✍️ Target Configuration")
        else:
            st.markdown("#### ✍️ Target Configuration")
        
        # Initialize target input with discovered host if selected
        initial_target = ""
        if 'hydra_target_from_discovery' in st.session_state:
            initial_target = st.session_state.hydra_target_from_discovery
        
        # Initialize target input value in session state if not exists
        if "hydra_target_input" not in st.session_state:
            st.session_state.hydra_target_input = initial_target
        elif initial_target:  # Update if we have a new target from discovery
            st.session_state.hydra_target_input = initial_target
        
        target_input = st.text_area(
            "Target Host(s)",
            value=st.session_state.hydra_target_input,
            placeholder="192.168.1.100\nexample.com\n10.0.0.1",
            help="Enter one or more target hosts (one per line). Supports IP addresses and hostnames.",
            height=100,
            key="hydra_target_input"
        )
        
        # Clear the discovery target after use
        if 'hydra_target_from_discovery' in st.session_state:
            del st.session_state.hydra_target_from_discovery
    
    with col2:
        # Protocol and port selection
        st.markdown("### 🔌 Protocol & Port")
        
        # Protocol selection with popular options
        protocol = st.selectbox(
            "Target Protocol",
            [
                "ssh",
                "ftp", 
                "telnet",
                "http-get",
                "http-post-form",
                "https-get",
                "https-post-form",
                "smb",
                "mysql",
                "postgres",
                "mssql",
                "oracle",
                "ldap",
                "vnc",
                "rdp",
                "snmp",
                "pop3",
                "imap",
                "smtp",
                "cisco",
                "cisco-enable"
            ],
            help="Select the protocol/service to attack"
        )
        
        # Port configuration
        use_custom_port = st.checkbox("Custom Port", help="Use non-standard port")
        if use_custom_port:
            custom_port = st.number_input("Port", min_value=1, max_value=65535, value=22)
        else:
            st.info("Using default port for selected protocol")
    
    # Authentication configuration
    st.markdown("### 🔐 Authentication Configuration")
    
    # Authentication mode selection
    auth_mode = st.radio(
        "Authentication Method:",
        [
            "Single User/Password",
            "Username List",
            "Password List", 
            "Both Lists",
            "Username File",
            "Password File",
            "Both Files"
        ],
        horizontal=False,
        help="Choose how to provide authentication credentials",
        key="hydra_auth_mode_radio"
    )
    
    username_input = ""
    password_input = ""
    username_list = ""
    password_list = ""
    
    # Authentication input based on mode
    if auth_mode == "Single User/Password":
        col_auth1, col_auth2 = st.columns(2)
        with col_auth1:
            username_input = st.text_input("Username", help="Single username to test")
        with col_auth2:
            password_input = st.text_input("Password", type="password", help="Single password to test")
    
    elif auth_mode == "Username List":
        col_auth1, col_auth2 = st.columns(2)
        with col_auth1:
            username_list = st.text_area(
                "Username List", 
                placeholder="admin\nroot\nuser\nadministrator",
                help="Enter usernames (one per line)",
                height=100
            )
        with col_auth2:
            password_input = st.text_input("Password", type="password", help="Single password to test against all usernames")
    
    elif auth_mode == "Password List":
        col_auth1, col_auth2 = st.columns(2)
        with col_auth1:
            username_input = st.text_input("Username", help="Single username to test")
        with col_auth2:
            password_list = st.text_area(
                "Password List",
                placeholder="password\n123456\nadmin\npassword123",
                help="Enter passwords (one per line)",
                height=100
            )
    
    elif auth_mode == "Both Lists":
        col_auth1, col_auth2 = st.columns(2)
        with col_auth1:
            username_list = st.text_area(
                "Username List",
                placeholder="admin\nroot\nuser",
                help="Enter usernames (one per line)",
                height=100
            )
        with col_auth2:
            password_list = st.text_area(
                "Password List",
                placeholder="password\n123456\nadmin",
                help="Enter passwords (one per line)",
                height=100
            )
    
    elif auth_mode == "Username File":
        username_file = st.file_uploader(
            "Upload Username File",
            type=["txt", "lst", "dic"],
            help="Upload a file containing usernames (one per line)",
            key="hydra_username_file_uploader"
        )
        if username_file:
            st.session_state['hydra_username_file'] = username_file
            st.success(f"📁 Uploaded: {username_file.name}")
        elif 'hydra_username_file' in st.session_state:
            username_file = st.session_state['hydra_username_file']
            st.info(f"📁 Using uploaded: {username_file.name}")
        
        password_input = st.text_input("Password", type="password", help="Single password to test")
    
    elif auth_mode == "Password File":
        username_input = st.text_input("Username", help="Single username to test")
        
        password_file = st.file_uploader(
            "Upload Password File",
            type=["txt", "lst", "dic"],
            help="Upload a file containing passwords (one per line)",
            key="hydra_password_file_uploader"
        )
        if password_file:
            st.session_state['hydra_password_file'] = password_file
            st.success(f"📁 Uploaded: {password_file.name}")
        elif 'hydra_password_file' in st.session_state:
            password_file = st.session_state['hydra_password_file']
            st.info(f"📁 Using uploaded: {password_file.name}")
    
    elif auth_mode == "Both Files":
        col_auth1, col_auth2 = st.columns(2)
        
        with col_auth1:
            username_file = st.file_uploader(
                "Upload Username File",
                type=["txt", "lst", "dic"],
                help="Upload a file containing usernames",
                key="hydra_both_files_username_uploader"
            )
            if username_file:
                st.session_state['hydra_both_files_username'] = username_file
                st.success(f"📁 Uploaded: {username_file.name}")
            elif 'hydra_both_files_username' in st.session_state:
                username_file = st.session_state['hydra_both_files_username']
                st.info(f"📁 Using uploaded: {username_file.name}")
        
        with col_auth2:
            password_file = st.file_uploader(
                "Upload Password File", 
                type=["txt", "lst", "dic"],
                help="Upload a file containing passwords",
                key="hydra_both_files_password_uploader"
            )
            if password_file:
                st.session_state['hydra_both_files_password'] = password_file
                st.success(f"📁 Uploaded: {password_file.name}")
            elif 'hydra_both_files_password' in st.session_state:
                password_file = st.session_state['hydra_both_files_password']
                st.info(f"📁 Using uploaded: {password_file.name}")
    
    # Get optimal thread recommendations
    thread_recommendations = get_optimal_thread_count()
    
    # Advanced options
    st.markdown("### ⚙️ Advanced Options")
    
    # Performance recommendations
    with st.expander("💡 Performance Recommendations", expanded=False):
        st.write("**Recommended Thread Counts Based on Your System:**")
        col_rec1, col_rec2, col_rec3, col_rec4 = st.columns(4)
        
        with col_rec1:
            st.metric("🐌 Conservative", thread_recommendations["conservative"], "Safe for all systems")
        with col_rec2:
            st.metric("⚖️ Moderate", thread_recommendations["moderate"], "Good balance")
        with col_rec3:
            st.metric("🚀 Aggressive", thread_recommendations["aggressive"], "High performance")
        with col_rec4:
            st.metric("🔥 Maximum", thread_recommendations["maximum"], "Use with caution")
        
        st.info("💡 **Tip**: Start with Conservative or Moderate settings. Monitor the performance dashboard above and increase threads if system is stable.")
    
    # Create columns for advanced options
    col_adv1, col_adv2, col_adv3 = st.columns(3)
    
    with col_adv1:
        threads = st.slider(
            "Parallel Tasks", 
            min_value=1, 
            max_value=min(64, thread_recommendations["maximum"]), 
            value=min(thread_recommendations["moderate"], 16), 
            help="Number of parallel connections. Check performance monitor above for optimal settings."
        )
        timeout = st.slider("Timeout (seconds)", min_value=1, max_value=300, value=30, help="Connection timeout per attempt")
    
    with col_adv2:
        wait_time = st.slider("Wait between attempts (seconds)", min_value=0, max_value=10, value=0, help="Delay between connection attempts")
        verbose = st.checkbox("Verbose output (-v)", value=True, help="Enable verbose output")
    
    with col_adv3:
        exit_on_first = st.checkbox("Exit after first success (-f)", value=False, help="Stop after finding first valid credential pair")
        continue_on_success = st.checkbox("Continue after success", value=True, help="Keep testing after finding valid credentials")
    
    # Protocol-specific options
    if protocol in ["http-get", "https-get", "http-post-form", "https-post-form"]:
        st.markdown("#### 🌐 HTTP/HTTPS Specific Options")
        col_http1, col_http2 = st.columns(2)
        
        with col_http1:
            http_path = st.text_input("Path", value="/", help="URL path to attack (e.g., /admin, /login)")
        
        with col_http2:
            if protocol in ["http-post-form", "https-post-form"]:
                post_data = st.text_input("POST Data", placeholder="username=^USER^&password=^PASS^", help="POST form data with ^USER^ and ^PASS^ placeholders")
    
    # Attack Configuration Display
    st.markdown("### 🎯 Attack Configuration")
    
    if target_input and target_input.strip():
        targets = [t.strip() for t in target_input.strip().split('\n') if t.strip()]
        st.write(f"**Targets:** {', '.join(targets)}")
        st.write(f"**Protocol:** {protocol}")
        if use_custom_port:
            st.write(f"**Port:** {custom_port}")
        st.write(f"**Authentication Mode:** {auth_mode}")
        st.write(f"**Threads:** {threads}, **Timeout:** {timeout}s")
    else:
        st.info("📝 Please enter target host(s) above to see attack configuration.")
    
    # Start attack button
    if st.button("🚀 Start Hydra Brute Force Attack", type="primary", use_container_width=True, key="hydra_start_attack_btn"):
        if not target_input or not target_input.strip():
            st.error("❌ Please enter at least one target host.")
        else:
            # Validate authentication configuration
            auth_valid = False
            auth_error = ""
            
            if auth_mode == "Single User/Password":
                if username_input and password_input:
                    auth_valid = True
                else:
                    auth_error = "Please provide both username and password."
            
            elif auth_mode == "Username List":
                if username_list and password_input:
                    auth_valid = True
                else:
                    auth_error = "Please provide username list and password."
            
            elif auth_mode == "Password List":
                if username_input and password_list:
                    auth_valid = True
                else:
                    auth_error = "Please provide username and password list."
            
            elif auth_mode == "Both Lists":
                if username_list and password_list:
                    auth_valid = True
                else:
                    auth_error = "Please provide both username and password lists."
            
            elif auth_mode == "Username File":
                if 'hydra_username_file' in st.session_state and password_input:
                    auth_valid = True
                else:
                    auth_error = "Please upload username file and provide password."
            
            elif auth_mode == "Password File":
                if username_input and 'hydra_password_file' in st.session_state:
                    auth_valid = True
                else:
                    auth_error = "Please provide username and upload password file."
            
            elif auth_mode == "Both Files":
                if 'hydra_both_files_username' in st.session_state and 'hydra_both_files_password' in st.session_state:
                    auth_valid = True
                else:
                    auth_error = "Please upload both username and password files."
            
            if not auth_valid:
                st.error(f"❌ Authentication configuration error: {auth_error}")
            else:
                # Build Hydra command
                targets = [t.strip() for t in target_input.strip().split('\n') if t.strip()]
                
                # Start building command for first target (Hydra handles one target at a time)
                target = targets[0]  # We'll handle multiple targets in a loop later if needed
                
                cmd = ["hydra"]
                
                # Add authentication options
                if auth_mode == "Single User/Password":
                    cmd.extend(["-l", username_input, "-p", password_input])
                elif auth_mode == "Username List":
                    # Create temporary username file
                    with open("/tmp/hydra_users.txt", "w") as f:
                        f.write(username_list)
                    cmd.extend(["-L", "/tmp/hydra_users.txt", "-p", password_input])
                elif auth_mode == "Password List":
                    # Create temporary password file
                    with open("/tmp/hydra_passwords.txt", "w") as f:
                        f.write(password_list)
                    cmd.extend(["-l", username_input, "-P", "/tmp/hydra_passwords.txt"])
                elif auth_mode == "Both Lists":
                    # Create temporary files
                    with open("/tmp/hydra_users.txt", "w") as f:
                        f.write(username_list)
                    with open("/tmp/hydra_passwords.txt", "w") as f:
                        f.write(password_list)
                    cmd.extend(["-L", "/tmp/hydra_users.txt", "-P", "/tmp/hydra_passwords.txt"])
                elif auth_mode == "Username File":
                    # Save uploaded file
                    username_file = st.session_state['hydra_username_file']
                    with open("/tmp/hydra_users_uploaded.txt", "wb") as f:
                        f.write(username_file.getbuffer())
                    cmd.extend(["-L", "/tmp/hydra_users_uploaded.txt", "-p", password_input])
                elif auth_mode == "Password File":
                    # Save uploaded file
                    password_file = st.session_state['hydra_password_file']
                    with open("/tmp/hydra_passwords_uploaded.txt", "wb") as f:
                        f.write(password_file.getbuffer())
                    cmd.extend(["-l", username_input, "-P", "/tmp/hydra_passwords_uploaded.txt"])
                elif auth_mode == "Both Files":
                    # Save uploaded files
                    username_file = st.session_state['hydra_both_files_username']
                    password_file = st.session_state['hydra_both_files_password']
                    with open("/tmp/hydra_users_uploaded.txt", "wb") as f:
                        f.write(username_file.getbuffer())
                    with open("/tmp/hydra_passwords_uploaded.txt", "wb") as f:
                        f.write(password_file.getbuffer())
                    cmd.extend(["-L", "/tmp/hydra_users_uploaded.txt", "-P", "/tmp/hydra_passwords_uploaded.txt"])
                
                # Add performance options
                cmd.extend(["-t", str(threads)])
                cmd.extend(["-w", str(timeout)])
                
                if wait_time > 0:
                    cmd.extend(["-W", str(wait_time)])
                
                if verbose:
                    cmd.append("-v")
                    
                if exit_on_first:
                    cmd.append("-f")
                
                # Add target and protocol
                if use_custom_port:
                    cmd.extend(["-s", str(custom_port)])
                
                cmd.append(target)
                cmd.append(protocol)
                
                # Add protocol-specific options
                if protocol in ["http-get", "https-get"] and 'http_path' in locals():
                    cmd.append(http_path)
                elif protocol in ["http-post-form", "https-post-form"] and 'post_data' in locals():
                    cmd.append(f"{http_path}:{post_data}")
                
                st.write(f"**Command:** `{' '.join(cmd)}`")
                
                # Warning about brute force attacks
                st.warning("⚠️ **Warning:** Brute force attacks can be detected by security systems and may trigger account lockouts or IP bans. Use responsibly and only on authorized systems!")
                
                # Progress indicators
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                # Run scan
                with st.spinner("Starting Hydra brute force attack..."):
                    output, error, return_code = run_hydra_scan(cmd, progress_bar, status_text)
                
                # Clean up temporary files
                try:
                    temp_files = [
                        "/tmp/hydra_users.txt",
                        "/tmp/hydra_passwords.txt", 
                        "/tmp/hydra_users_uploaded.txt",
                        "/tmp/hydra_passwords_uploaded.txt"
                    ]
                    for temp_file in temp_files:
                        if os.path.exists(temp_file):
                            os.remove(temp_file)
                except:
                    pass
                
                if return_code == 0 or output:  # Hydra might return non-zero even on success
                    st.success("✅ Hydra brute force attack completed!")
                    
                    # Add clear results button
                    col_clear1, col_clear2 = st.columns([1, 4])
                    with col_clear1:
                        if st.button("🔄 Clear & New Attack", help="Clear results and start a new attack", key="hydra_clear_new_attack_btn"):
                            # Clear session state
                            if 'last_hydra_results' in st.session_state:
                                del st.session_state['last_hydra_results']
                            if 'last_hydra_command' in st.session_state:
                                del st.session_state['last_hydra_command']
                            st.rerun()
                    
                    # Parse and display results
                    scan_results = parse_hydra_output(output)
                    
                    # Store results in session state for download
                    st.session_state['last_hydra_results'] = scan_results
                    st.session_state['last_hydra_command'] = ' '.join(cmd)
                    
                    # Display results
                    st.subheader("📊 Attack Results")
                    
                    # Summary metrics
                    col_metric1, col_metric2, col_metric3, col_metric4 = st.columns(4)
                    with col_metric1:
                        st.metric("Successful Logins", len(scan_results.get('successful_logins', [])))
                    with col_metric2:
                        st.metric("Total Attempts", scan_results.get('total_attempts', 0))
                    with col_metric3:
                        st.metric("Failed Attempts", scan_results.get('failed_attempts', 0))
                    with col_metric4:
                        st.metric("Target Service", f"{scan_results.get('target', 'N/A')} ({scan_results.get('service', 'N/A')})")
                    
                    # Successful logins section
                    if scan_results.get('successful_logins'):
                        st.subheader("🎯 Successful Logins Found!")
                        
                        # Create DataFrame for successful logins
                        login_data = []
                        for login in scan_results['successful_logins']:
                            login_data.append({
                                'Host': login.get('host', 'N/A'),
                                'Port': login.get('port', 'N/A'),
                                'Service': login.get('service', 'N/A'),
                                'Username': login.get('username', 'N/A'),
                                'Password': login.get('password', 'N/A')
                            })
                        
                        if login_data:
                            df_logins = pd.DataFrame(login_data)
                            st.dataframe(df_logins, use_container_width=True)
                            
                            # Security warning for found credentials
                            st.warning("⚠️ **Security Alert:** Valid credentials were found! These should be immediately secured or changed on the target system.")
                    else:
                        st.info("🔒 No successful logins found with the provided credentials and configuration.")
                    
                    # Raw output section
                    with st.expander("📄 Raw Hydra Output", expanded=False):
                        st.code(output, language="text")
                    
                    # Download section
                    st.subheader("💾 Download Results")
                    
                    col_download1, col_download2, col_download3 = st.columns(3)
                    
                    with col_download1:
                        # HTML Report
                        html_report = create_hydra_html_report(scan_results, ' '.join(cmd))
                        st.download_button(
                            label="📄 Download HTML Report",
                            data=html_report,
                            file_name=f"hydra_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                            mime="text/html"
                        )
                    
                    with col_download2:
                        # JSON Results
                        json_results = json.dumps(scan_results, indent=2, default=str)
                        st.download_button(
                            label="📊 Download JSON Results",
                            data=json_results,
                            file_name=f"hydra_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                            mime="application/json"
                        )
                    
                    with col_download3:
                        # Raw Output
                        st.download_button(
                            label="📝 Download Raw Output",
                            data=output,
                            file_name=f"hydra_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                            mime="text/plain"
                        )
                
                else:
                    st.error("❌ Hydra attack failed!")
                    
                    col_error_clear1, col_error_clear2 = st.columns([1, 4])
                    with col_error_clear1:
                        if st.button("🔄 Try New Attack", help="Clear and try a different attack", key="hydra_try_new_attack_btn"):
                            st.rerun()
                    
                    if error:
                        st.error(f"**Error:** {error}")
                    
                    if output:
                        st.subheader("📄 Partial Output")
                        st.code(output, language="text")

if __name__ == "__main__":
    show_hydra_interface()
