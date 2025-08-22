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

def parse_medusa_output(output):
    """Parse Medusa output and structure it for display"""
    lines = output.split('\n')
    results = {
        'summary': '',
        'successful_logins': [],
        'failed_attempts': 0,
        'total_attempts': 0,
        'raw_output': output
    }
    
    for line in lines:
        line = line.strip()
        
        # Parse successful logins
        if 'SUCCESS' in line.upper() and 'login' in line.lower():
            # Extract host, username, password from success line
            parts = line.split()
            success_info = {
                'host': '',
                'username': '',
                'password': '',
                'service': '',
                'full_line': line
            }
            
            # Try to extract details from common Medusa output formats
            if '[SUCCESS]' in line:
                # Format: [SUCCESS] host:port - login:"user" - password:"pass"
                if 'login:' in line and 'password:' in line:
                    login_part = line.split('login:')[1].split('-')[0].strip().strip('"')
                    pass_part = line.split('password:')[1].strip().strip('"')
                    host_part = line.split('[SUCCESS]')[1].split('-')[0].strip()
                    
                    success_info['username'] = login_part
                    success_info['password'] = pass_part
                    success_info['host'] = host_part
            
            results['successful_logins'].append(success_info)
        
        # Count attempts
        if 'attempt' in line.lower() or 'trying' in line.lower():
            results['total_attempts'] += 1
        
        # Extract summary information
        if 'ACCOUNT FOUND' in line.upper():
            results['summary'] = line
    
    results['failed_attempts'] = results['total_attempts'] - len(results['successful_logins'])
    
    return results

def run_medusa_scan(command, progress_bar, status_text):
    """Run Medusa brute force scan with progress updates and real-time monitoring"""
    try:
        # Get system monitor for real-time performance tracking
        monitor = get_global_monitor()
        
        # Create containers for monitoring during attack
        monitoring_container = st.container()
        
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
        
        # Read output line by line
        while True:
            output_line = process.stdout.readline()
            if output_line == '' and process.poll() is not None:
                break
            if output_line:
                output += output_line
                # Update status with last line
                if 'trying' in output_line.lower() or 'attempt' in output_line.lower():
                    attempt_count += 1
                    status_text.text(f"Attempting login {attempt_count}... {output_line.strip()[:50]}...")
                    # Rough progress estimation based on attempts
                    progress_bar.progress(min(attempt_count / 100, 0.9))
                elif 'SUCCESS' in output_line.upper():
                    status_text.text(f"✅ Found credentials! {output_line.strip()}")
                
                # Update monitoring dashboard every 2 seconds during attack
                current_time = time.time()
                if current_time - last_monitor_update > 2.0:
                    try:
                        # Update monitoring dashboard with current metrics
                        current_metrics = monitor.get_latest_metrics()
                        if current_metrics:
                            # Show key metrics inline during attack
                            status_text.text(f"Login attempt {attempt_count} | CPU: {current_metrics.cpu_percent:.1f}% | Memory: {current_metrics.memory_percent:.1f}% | Connections: {current_metrics.active_connections}")
                        last_monitor_update = current_time
                    except:
                        # Don't let monitoring errors interrupt the attack
                        pass
        
        # Get any remaining output
        remaining_output, error_output = process.communicate()
        output += remaining_output
        
        progress_bar.progress(1.0)
        status_text.text("Brute force scan completed!")
        
        return output, error_output, process.returncode
        
    except Exception as e:
        return "", str(e), 1

def create_medusa_html_report(scan_results, scan_command):
    """Create an HTML report of the Medusa scan results"""
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Medusa Brute Force Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            .header {{ background-color: #dc2626; color: white; padding: 20px; text-align: center; }}
            .summary {{ background-color: #f8fafc; padding: 15px; margin: 20px 0; border-left: 4px solid #dc2626; }}
            .success {{ background-color: #dcfce7; padding: 15px; margin: 20px 0; border-left: 4px solid #16a34a; }}
            .credentials-table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
            .credentials-table th, .credentials-table td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            .credentials-table th {{ background-color: #fee2e2; }}
            .success-row {{ background-color: #dcfce7; }}
            .stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
            .stat-box {{ text-align: center; padding: 15px; background-color: #f1f5f9; border-radius: 8px; }}
            .raw-output {{ background-color: #1f2937; color: #f9fafb; padding: 20px; font-family: monospace; white-space: pre-wrap; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🔓 Medusa Brute Force Report</h1>
            <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="summary">
            <h2>Scan Command</h2>
            <code>{scan_command}</code>
        </div>
        
        <div class="stats">
            <div class="stat-box">
                <h3>{len(scan_results.get('successful_logins', []))}</h3>
                <p>Successful Logins</p>
            </div>
            <div class="stat-box">
                <h3>{scan_results.get('total_attempts', 0)}</h3>
                <p>Total Attempts</p>
            </div>
            <div class="stat-box">
                <h3>{scan_results.get('failed_attempts', 0)}</h3>
                <p>Failed Attempts</p>
            </div>
        </div>
    """
    
    # Add successful logins
    if scan_results.get('successful_logins'):
        html_content += """
        <div class="success">
            <h2>🎯 Successful Logins Found</h2>
            <table class="credentials-table">
                <tr><th>Host</th><th>Username</th><th>Password</th><th>Details</th></tr>
        """
        for login in scan_results['successful_logins']:
            html_content += f"""
            <tr class="success-row">
                <td>{login.get('host', 'N/A')}</td>
                <td><strong>{login.get('username', 'N/A')}</strong></td>
                <td><strong>{login.get('password', 'N/A')}</strong></td>
                <td>{login.get('full_line', '')}</td>
            </tr>
            """
        html_content += "</table></div>"
    else:
        html_content += """
        <div class="summary">
            <h2>🔒 No Successful Logins Found</h2>
            <p>The brute force attack did not discover any valid credentials with the provided wordlists.</p>
        </div>
        """
    
    # Add raw output
    html_content += f"""
        <div class="summary">
            <h2>Raw Medusa Output</h2>
            <div class="raw-output">{scan_results.get('raw_output', '')}</div>
        </div>
    </body>
    </html>
    """
    
    return html_content

def show_medusa_interface():
    """Main Medusa brute force interface"""
    st.header("🔓 Medusa Brute Force Scanner")
    
    st.info("💡 **Medusa** is a speedy, massively parallel, modular, login brute-forcer for network services. Use responsibly and only on authorized systems.")
    
    # Configuration in main content area
    st.subheader("⚙️ Brute Force Configuration")
    
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
                key="medusa_host_selectbox"
            )
            
            # Auto-populate target field when selection changes
            if selected_host:
                selected_ip = extract_ip_from_selection(selected_host)
                st.session_state.medusa_target_from_discovery = selected_ip
                st.success(f"✅ Auto-populated target: {selected_ip}")
            
            st.markdown("#### ✍️ Target Configuration")
        else:
            st.markdown("#### ✍️ Target Configuration")
        
        # Initialize target input with discovered host if selected
        initial_target = ""
        if 'medusa_target_from_discovery' in st.session_state:
            initial_target = st.session_state.medusa_target_from_discovery
            # Don't delete immediately - let it persist for the current render
        
        # Initialize target input value in session state if not exists
        if "medusa_target_input" not in st.session_state:
            st.session_state.medusa_target_input = initial_target
        elif initial_target:  # Update if we have a new target from discovery
            st.session_state.medusa_target_input = initial_target
            
        target_input = st.text_area(
            "Target Host(s)",
            value=st.session_state.medusa_target_input,
            placeholder="192.168.1.100\nexample.com\n10.0.0.1",
            help="Enter one or more target hosts (one per line). Supports IP addresses and hostnames.",
            height=100,
            key="medusa_target_input"
        )
    
        # Service/Protocol selection
        st.markdown("### 🌐 Service Configuration")
        service_type = st.selectbox(
            "Target Service",
            [
                "SSH (ssh)",
                "FTP (ftp)",
                "HTTP Basic Auth (http)",
                "HTTPS Basic Auth (https)",
                "Telnet (telnet)",
                "POP3 (pop3)",
                "IMAP (imap)",
                "SMTP (smtp)",
                "MySQL (mysql)",
                "PostgreSQL (postgres)",
                "VNC (vnc)",
                "RDP (rdp)",
                "SMB/NetBIOS (smb)"
            ],
            key="medusa_service_selectbox"
        )
    
    with col2:
        # Port specification
        st.markdown("### 🔌 Port Configuration")
        port_input = st.number_input(
            "Port (optional)",
            min_value=1,
            max_value=65535,
            value=None,
            help="Leave empty to use default port for the selected service"
        )
    
    # Authentication configuration
    st.markdown("### 🔐 Authentication Options")
    
    # Group authentication options logically
    st.markdown("**Manual Entry Options:**")
    manual_options = ["Single User/Password", "Username List", "Password List", "Both Lists"]
    st.markdown("**File Upload Options:**")
    file_options = ["Username File", "Password File", "Both Files", "Combined File"]
    
    auth_mode = st.radio(
        "Choose Authentication Method:",
        manual_options + file_options,
        horizontal=False,
        help="Choose how to provide authentication credentials",
        key="auth_mode_radio"
    )
    
    username_input = ""
    password_input = ""
    username_list = ""
    password_list = ""
    username_file = None
    password_file = None
    combined_file = None
    
    # Create columns for authentication inputs
    col_auth1, col_auth2 = st.columns(2)
    
    if auth_mode == "Single User/Password":
        with col_auth1:
            username_input = st.text_input("Username", placeholder="admin")
        with col_auth2:
            password_input = st.text_input("Password", placeholder="password", type="password")
    
    elif auth_mode == "Username List":
        with col_auth1:
            username_list = st.text_area(
                "Username List",
                placeholder="admin\nroot\nuser\nadministrator\nguest",
                help="Enter usernames one per line",
                height=120
            )
        with col_auth2:
            password_input = st.text_input("Password", placeholder="password", type="password")
    
    elif auth_mode == "Password List":
        with col_auth1:
            username_input = st.text_input("Username", placeholder="admin")
        with col_auth2:
            password_list = st.text_area(
                "Password List",
                placeholder="password\n123456\nadmin\nroot\npassword123",
                help="Enter passwords one per line",
                height=120
            )
    
    elif auth_mode == "Both Lists":
        with col_auth1:
            username_list = st.text_area(
                "Username List",
                placeholder="admin\nroot\nuser\nadministrator",
                help="Enter usernames one per line",
                height=120
            )
        with col_auth2:
            password_list = st.text_area(
                "Password List",
                placeholder="password\n123456\nadmin\nroot\npassword123",
                help="Enter passwords one per line",
                height=120
            )
    
    elif auth_mode == "Username File":
        with col_auth1:
            username_file = st.file_uploader(
                "Upload Username File",
                type=['txt', 'lst', 'dic'],
                help="Upload a text file with usernames (one per line)",
                key="username_file_uploader"
            )
            if username_file:
                st.session_state['username_file'] = username_file
                st.success(f"📁 Uploaded: {username_file.name}")
            elif 'username_file' in st.session_state:
                username_file = st.session_state['username_file']
                st.success(f"📁 Using uploaded: {username_file.name}")
        with col_auth2:
            password_input = st.text_input("Password", placeholder="password", type="password")
    
    elif auth_mode == "Password File":
        with col_auth1:
            username_input = st.text_input("Username", placeholder="admin")
        with col_auth2:
            password_file = st.file_uploader(
                "Upload Password File",
                type=['txt', 'lst', 'dic'],
                help="Upload a text file with passwords (one per line)",
                key="password_file_uploader"
            )
            if password_file:
                st.session_state['password_file'] = password_file
                st.success(f"📁 Uploaded: {password_file.name}")
            elif 'password_file' in st.session_state:
                password_file = st.session_state['password_file']
                st.success(f"📁 Using uploaded: {password_file.name}")
    
    elif auth_mode == "Both Files":
        with col_auth1:
            username_file = st.file_uploader(
                "Upload Username File",
                type=['txt', 'lst', 'dic'],
                help="Upload a text file with usernames (one per line)",
                key="both_files_username_uploader"
            )
            if username_file:
                st.session_state['both_files_username'] = username_file
                st.success(f"📁 Uploaded: {username_file.name}")
            elif 'both_files_username' in st.session_state:
                username_file = st.session_state['both_files_username']
                st.success(f"📁 Using uploaded: {username_file.name}")
        with col_auth2:
            password_file = st.file_uploader(
                "Upload Password File",
                type=['txt', 'lst', 'dic'],
                help="Upload a text file with passwords (one per line)",
                key="both_files_password_uploader"
            )
            if password_file:
                st.session_state['both_files_password'] = password_file
                st.success(f"📁 Uploaded: {password_file.name}")
            elif 'both_files_password' in st.session_state:
                password_file = st.session_state['both_files_password']
                st.success(f"📁 Using uploaded: {password_file.name}")
    
    elif auth_mode == "Combined File":
        st.info("💡 **Combined File Format:** Each line should contain 'username:password' or 'username password'")
        combined_file = st.file_uploader(
            "Upload Combined Credentials File",
            type=['txt', 'lst', 'dic'],
            help="Upload a file with username:password pairs (one per line)",
            key="combined_file_uploader"
        )
        if combined_file:
            st.session_state['combined_file'] = combined_file
            st.success(f"📁 Uploaded: {combined_file.name}")
            st.info("📋 The file will be processed to extract usernames and passwords automatically.")
        elif 'combined_file' in st.session_state:
            combined_file = st.session_state['combined_file']
            st.success(f"📁 Using uploaded: {combined_file.name}")
            st.info("📋 The file will be processed to extract usernames and passwords automatically.")
    
    # System Performance Monitoring
    st.markdown("### 📊 System Performance Monitor")
    
    # Get system monitor and create dashboard
    monitor = get_global_monitor()
    monitoring_container = st.container()
    create_monitoring_dashboard(monitor, monitoring_container)
    
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
        
        st.info("💡 **Tip**: Start with Conservative or Moderate settings. Monitor the performance dashboard above and increase threads if CPU usage is low and system is stable.")
    
    # Create columns for advanced options
    col_adv1, col_adv2, col_adv3 = st.columns(3)
    
    with col_adv1:
        threads = st.slider(
            "Threads", 
            min_value=1, 
            max_value=90, 
            value=min(thread_recommendations["moderate"], 90), 
            help="Number of parallel threads. Check performance monitor above for optimal settings."
        )
        timeout = st.slider("Timeout (seconds)", min_value=1, max_value=60, value=30, help="Connection timeout")
    
    with col_adv2:
        verbose = st.checkbox("Verbose output (-v)", value=True, help="Enable verbose output")
        continue_on_success = st.checkbox("Continue after success (-F)", help="Continue testing after finding valid credentials")
    
    with col_adv3:
        exit_on_first = st.checkbox("Exit on first success (-f)", value=True, help="Exit after finding first valid credential pair")
    
    # Group advanced options into dictionary for compatibility
    advanced_options = {
        "threads": threads,
        "timeout": timeout,
        "verbose": verbose,
        "continue_on_success": continue_on_success,
        "exit_on_first": exit_on_first
    }
    
    # Attack Configuration
    st.markdown("### 🎯 Attack Configuration")
    
    # Display current configuration
    if target_input and target_input.strip():
        targets = [t.strip() for t in target_input.split('\n') if t.strip()]
        st.write(f"**Targets:** {', '.join(targets)}")
        st.write(f"**Service:** {service_type}")
        
        if port_input:
            st.write(f"**Port:** {port_input}")
        
        st.write(f"**Authentication Mode:** {auth_mode}")
        st.write(f"**Threads:** {advanced_options['threads']}")
        st.write(f"**Timeout:** {advanced_options['timeout']} seconds")
    else:
        st.info("📝 Please enter target host(s) above to see attack configuration.")
        
    # Always show the attack button (moved outside the target_input condition)
    if st.button("🚀 Start Brute Force Attack", type="primary", use_container_width=True, key="medusa_start_attack_btn"):
        st.write("🔍 DEBUG: Attack button clicked!")
        st.write(f"🔍 DEBUG: target_input.strip() = '{target_input.strip()}'")
        st.write(f"🔍 DEBUG: auth_mode = '{auth_mode}'")
        
        if not target_input.strip():
            st.error("Please enter at least one target host.")
        elif auth_mode == "Single User/Password" and (not username_input or not password_input):
            st.error("Please enter both username and password for single credential mode.")
        elif auth_mode == "Username List" and (not username_list or not password_input):
            st.error("Please enter username list and password.")
        elif auth_mode == "Password List" and (not username_input or not password_list):
            st.error("Please enter username and password list.")
        elif auth_mode == "Both Lists" and (not username_list or not password_list):
            st.error("Please enter both username list and password list.")
        elif auth_mode == "Username File" and (not st.session_state.get('username_file') or not password_input):
            st.error("Please upload username file and enter password.")
        elif auth_mode == "Password File" and (not username_input or not st.session_state.get('password_file')):
            st.error("Please enter username and upload password file.")
        elif auth_mode == "Both Files" and (not st.session_state.get('both_files_username') or not st.session_state.get('both_files_password')):
            st.write("🔍 DEBUG: Both Files validation failed")
            st.error("Please upload both username and password files.")
        elif auth_mode == "Combined File" and not st.session_state.get('combined_file'):
            st.error("Please upload a combined credentials file.")
        else:
            st.write("🔍 DEBUG: All validations passed! Starting command building...")
            st.write(f"🔍 DEBUG: auth_mode = '{auth_mode}'")
            targets = [t.strip() for t in target_input.split('\n') if t.strip()]
            st.write(f"🔍 DEBUG: targets = {targets}")
            
            # Validate targets
            invalid_targets = []
            for target in targets:
                if not (validate_ip(target) or validate_hostname(target)):
                    invalid_targets.append(target)
            
            if invalid_targets:
                st.error(f"Invalid targets: {', '.join(invalid_targets)}")
            else:
                # Build command
                st.write("🔍 DEBUG: Starting command building process")
                st.write(f"🔍 DEBUG: About to build command for auth_mode: {auth_mode}")
                cmd = ["medusa"]
                
                # Add service module
                service_flag = service_type.split('(')[-1].replace(')', '')
                cmd.extend(["-M", service_flag])
                
                # Add targets
                for target in targets:
                    cmd.extend(["-h", target])
                
                # Add port if specified
                if port_input:
                    cmd.extend(["-n", str(port_input)])
                    
                                    # Add authentication options
                st.write(f"🔍 DEBUG: Adding authentication options for: {auth_mode}")
                if auth_mode == "Single User/Password":
                    cmd.extend(["-u", username_input])
                    cmd.extend(["-p", password_input])
                
                elif auth_mode == "Username List":
                    # Create temporary username file
                    username_file_path = "/tmp/medusa_users.txt"
                    with open(username_file_path, 'w') as f:
                        f.write(username_list)
                    cmd.extend(["-U", username_file_path])
                    cmd.extend(["-p", password_input])
                
                elif auth_mode == "Password List":
                    cmd.extend(["-u", username_input])
                    # Create temporary password file
                    password_file_path = "/tmp/medusa_passwords.txt"
                    with open(password_file_path, 'w') as f:
                        f.write(password_list)
                    cmd.extend(["-P", password_file_path])
                
                elif auth_mode == "Both Lists":
                    # Create temporary files
                    username_file_path = "/tmp/medusa_users.txt"
                    password_file_path = "/tmp/medusa_passwords.txt"
                    with open(username_file_path, 'w') as f:
                        f.write(username_list)
                    with open(password_file_path, 'w') as f:
                        f.write(password_list)
                    cmd.extend(["-U", username_file_path])
                    cmd.extend(["-P", password_file_path])
                
                elif auth_mode == "Username File":
                    # Save uploaded username file
                    username_file = st.session_state.get('username_file')
                    username_file_path = "/tmp/medusa_users_uploaded.txt"
                    with open(username_file_path, 'wb') as f:
                        f.write(username_file.getvalue())
                    cmd.extend(["-U", username_file_path])
                    cmd.extend(["-p", password_input])
                
                elif auth_mode == "Password File":
                    cmd.extend(["-u", username_input])
                    # Save uploaded password file
                    password_file = st.session_state.get('password_file')
                    password_file_path = "/tmp/medusa_passwords_uploaded.txt"
                    with open(password_file_path, 'wb') as f:
                        f.write(password_file.getvalue())
                    cmd.extend(["-P", password_file_path])
                
                elif auth_mode == "Both Files":
                    st.write("🔍 DEBUG: Entering Both Files command building section")
                    # Save uploaded username file
                    username_file = st.session_state.get('both_files_username')
                    st.write(f"🔍 DEBUG: Retrieved username file: {username_file.name if username_file else 'None'}")
                    username_file_path = "/tmp/medusa_users_uploaded.txt"
                    with open(username_file_path, 'wb') as f:
                        f.write(username_file.getvalue())
                    st.write(f"🔍 DEBUG: Saved username file to {username_file_path}")
                    
                    # Save uploaded password file
                    password_file = st.session_state.get('both_files_password')
                    st.write(f"🔍 DEBUG: Retrieved password file: {password_file.name if password_file else 'None'}")
                    password_file_path = "/tmp/medusa_passwords_uploaded.txt"
                    with open(password_file_path, 'wb') as f:
                        f.write(password_file.getvalue())
                    st.write(f"🔍 DEBUG: Saved password file to {password_file_path}")
                    
                    cmd.extend(["-U", username_file_path])
                    cmd.extend(["-P", password_file_path])
                    st.write(f"🔍 DEBUG: Added -U and -P flags to command")
                    st.write(f"🔍 DEBUG: Command after adding files: {' '.join(cmd)}")
                    
                elif auth_mode == "Combined File":
                    # Process combined file to extract usernames and passwords
                    combined_file = st.session_state.get('combined_file')
                    combined_content = combined_file.getvalue().decode('utf-8')
                    usernames = []
                    passwords = []
                    
                    for line in combined_content.strip().split('\n'):
                        line = line.strip()
                        if not line or line.startswith('#'):  # Skip empty lines and comments
                            continue
                        
                        # Try different separators
                        if ':' in line:
                            parts = line.split(':', 1)
                        elif ' ' in line:
                            parts = line.split(' ', 1)
                        elif '\t' in line:
                            parts = line.split('\t', 1)
                        else:
                            continue  # Skip malformed lines
                        
                        if len(parts) == 2:
                            usernames.append(parts[0].strip())
                            passwords.append(parts[1].strip())
                    
                    # Create temporary files
                    username_file_path = "/tmp/medusa_users_combined.txt"
                    password_file_path = "/tmp/medusa_passwords_combined.txt"
                    
                    with open(username_file_path, 'w') as f:
                        f.write('\n'.join(usernames))
                    with open(password_file_path, 'w') as f:
                        f.write('\n'.join(passwords))
                    
                    cmd.extend(["-U", username_file_path])
                    cmd.extend(["-P", password_file_path])
                    
                    st.info(f"📊 Extracted {len(usernames)} username/password pairs from combined file")
                
                # Add advanced options
                cmd.extend(["-t", str(advanced_options["threads"])])
                cmd.extend(["-T", str(advanced_options["timeout"])])
                
                if advanced_options["verbose"]:
                    cmd.append("-v")
                if advanced_options["continue_on_success"]:
                    cmd.append("-F")
                if advanced_options["exit_on_first"]:
                    cmd.append("-f")
                
                # Debug output
                st.write(f"**Debug Info:**")
                st.write(f"- Authentication Mode: {auth_mode}")
                st.write(f"- Session State Keys: {list(st.session_state.keys())}")
                st.write(f"- Username File in Session: {'username_file' in st.session_state}")
                st.write(f"- Password File in Session: {'password_file' in st.session_state}")
                st.write(f"- Both Files Username in Session: {'both_files_username' in st.session_state}")
                st.write(f"- Both Files Password in Session: {'both_files_password' in st.session_state}")
                st.write(f"- Combined File in Session: {'combined_file' in st.session_state}")
                
                if auth_mode == "Both Files":
                    st.write(f"- Both Files Username File: {st.session_state.get('both_files_username').name if st.session_state.get('both_files_username') else 'None'}")
                    st.write(f"- Both Files Password File: {st.session_state.get('both_files_password').name if st.session_state.get('both_files_password') else 'None'}")
                
                st.write(f"**Command:** `{' '.join(cmd)}`")
                
                # Warning about brute force attacks
                st.warning("⚠️ **Warning:** Brute force attacks can be detected by security systems and may trigger account lockouts. Use responsibly!")
                
                # Progress indicators
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                # Run scan
                with st.spinner("Starting brute force attack..."):
                    output, error, return_code = run_medusa_scan(cmd, progress_bar, status_text)
                
                # Clean up temporary files
                try:
                    temp_files = [
                        "/tmp/medusa_users.txt",
                        "/tmp/medusa_passwords.txt",
                        "/tmp/medusa_users_uploaded.txt",
                        "/tmp/medusa_passwords_uploaded.txt",
                        "/tmp/medusa_users_combined.txt",
                        "/tmp/medusa_passwords_combined.txt"
                    ]
                    for temp_file in temp_files:
                        if os.path.exists(temp_file):
                            os.remove(temp_file)
                except:
                    pass
                
                if return_code == 0 or output:  # Medusa might return non-zero even on success
                    st.success("✅ Brute force attack completed!")
                    
                    # Add clear results button
                    col_clear1, col_clear2 = st.columns([1, 4])
                    with col_clear1:
                        if st.button("🔄 Clear & New Attack", help="Clear results and start a new attack", key="medusa_clear_new_attack_btn"):
                            # Clear session state
                            if 'last_medusa_results' in st.session_state:
                                del st.session_state['last_medusa_results']
                            if 'last_medusa_command' in st.session_state:
                                del st.session_state['last_medusa_command']
                            st.rerun()
                    
                    # Parse and display results
                    scan_results = parse_medusa_output(output)
                    
                    # Store results in session state for download
                    st.session_state['last_medusa_results'] = scan_results
                    st.session_state['last_medusa_command'] = ' '.join(cmd)
                    
                    # Display results
                    st.subheader("📊 Attack Results")
                    
                    if scan_results['successful_logins']:
                        st.success(f"🎯 Found {len(scan_results['successful_logins'])} successful login(s)!")
                        
                        # Display successful logins in a table
                        login_data = []
                        for login in scan_results['successful_logins']:
                            login_data.append({
                                'Host': login.get('host', 'N/A'),
                                'Username': login.get('username', 'N/A'),
                                'Password': login.get('password', 'N/A'),
                                'Details': login.get('full_line', '')
                            })
                        
                        if login_data:
                            df = pd.DataFrame(login_data)
                            st.dataframe(df, use_container_width=True)
                    else:
                        st.info("🔒 No successful logins found with the provided credentials.")
                    
                    # Statistics
                    col_stat1, col_stat2, col_stat3 = st.columns(3)
                    with col_stat1:
                        st.metric("Successful Logins", len(scan_results['successful_logins']))
                    with col_stat2:
                        st.metric("Total Attempts", scan_results['total_attempts'])
                    with col_stat3:
                        st.metric("Failed Attempts", scan_results['failed_attempts'])
                    
                    # Raw output
                    with st.expander("🔍 Raw Medusa Output"):
                        st.code(output, language="text")
                        
                else:
                    st.error(f"❌ Brute force attack failed with return code {return_code}")
                    if error:
                        st.error(f"Error: {error}")
                    if output:
                        st.code(output, language="text")
                    
                    # Add clear button for failed attacks too
                    if st.button("🔄 Try New Attack", help="Clear and try a different attack", key="medusa_try_new_attack_btn"):
                        st.rerun()
    
    with col2:
        st.subheader("📥 Download Results")
        
        if 'last_medusa_results' in st.session_state:
            # HTML Report
            html_report = create_medusa_html_report(
                st.session_state['last_medusa_results'],
                st.session_state['last_medusa_command']
            )
            
            st.download_button(
                label="📄 Download HTML Report",
                data=html_report,
                file_name=f"medusa_attack_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                mime="text/html",
                use_container_width=True
            )
            
            # JSON Report
            json_report = json.dumps(st.session_state['last_medusa_results'], indent=2)
            st.download_button(
                label="📋 Download JSON Report",
                data=json_report,
                file_name=f"medusa_attack_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True
            )
            
            # Raw Output
            st.download_button(
                label="📝 Download Raw Output",
                data=st.session_state['last_medusa_results']['raw_output'],
                file_name=f"medusa_attack_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain",
                use_container_width=True
            )
        else:
            st.info("Run an attack to enable downloads")
        
        # Help section
        st.subheader("ℹ️ Help & Tips")
        
        with st.expander("🎯 Supported Services"):
            st.markdown("""
            - **SSH:** Secure Shell (port 22)
            - **FTP:** File Transfer Protocol (port 21)
            - **HTTP/HTTPS:** Web authentication
            - **Telnet:** Terminal access (port 23)
            - **POP3/IMAP:** Email protocols
            - **SMTP:** Mail transfer (port 25)
            - **MySQL/PostgreSQL:** Database services
            - **VNC:** Remote desktop (port 5900)
            - **RDP:** Windows Remote Desktop
            - **SMB:** Windows file sharing
            """)
        
        with st.expander("🔐 Authentication Modes"):
            st.markdown("""
            - **Single User/Password:** Test one credential pair
            - **Username List:** Multiple users, one password
            - **Password List:** One user, multiple passwords
            - **Both Lists:** All combinations of users and passwords
            """)
        
        with st.expander("⚠️ Legal & Ethical Use"):
            st.markdown("""
            **Only use on systems you own or have explicit permission to test:**
            - Authorized penetration testing
            - Security auditing with permission
            - Testing your own systems
            
            **Avoid:**
            - Unauthorized access attempts
            - Attacks against systems you don't own
            - Violating terms of service
            """)
        
        with st.expander("🛡️ Detection Avoidance"):
            st.markdown("""
            - **Use fewer threads** to avoid detection
            - **Increase timeout** for slower, stealthier attacks
            - **Monitor for account lockouts** 
            - **Use realistic username/password lists**
            - **Consider time delays** between attempts
            """)
