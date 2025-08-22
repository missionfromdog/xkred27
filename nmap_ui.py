import streamlit as st
import subprocess
import json
import xml.etree.ElementTree as ET
import pandas as pd
import time
import re
import os
import base64
from datetime import datetime
import threading
import queue
import getpass

# Page configuration
st.set_page_config(
    page_title="XKRed27 Nmap Scanner",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Theme is configured via .streamlit/config.toml

# Custom CSS for better styling
st.markdown("""
<style>
.main-header {
    font-size: 2.5rem;
    color: #1e3a8a;
    text-align: center;
    margin-bottom: 2rem;
    font-weight: bold;
}
.scan-box {
    background-color: #f8fafc;
    padding: 1.5rem;
    border-radius: 0.5rem;
    border-left: 4px solid #3b82f6;
    margin: 1rem 0;
}
.result-box {
    background-color: #f1f5f9;
    padding: 1rem;
    border-radius: 0.5rem;
    margin: 0.5rem 0;
    font-family: monospace;
}
.warning-box {
    background-color: #fef3c7;
    padding: 1rem;
    border-radius: 0.5rem;
    border-left: 4px solid #f59e0b;
    margin: 1rem 0;
}
</style>
""", unsafe_allow_html=True)

def validate_ip(ip):
    """Validate IP address format"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(pattern, ip):
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    return False

def validate_ip_range(ip_range):
    """Validate IP range or CIDR notation"""
    # CIDR notation
    if '/' in ip_range:
        ip, cidr = ip_range.split('/')
        try:
            cidr = int(cidr)
            return validate_ip(ip) and 0 <= cidr <= 32
        except ValueError:
            return False
    
    # Range notation (e.g., 192.168.1.1-10)
    if '-' in ip_range:
        if ip_range.count('-') == 1:
            base_ip, end = ip_range.rsplit('.', 1)[0], ip_range.rsplit('.', 1)[1]
            if '-' in end:
                start_end, end_num = end.split('-')
                try:
                    start_num = int(start_end)
                    end_num = int(end_num)
                    return validate_ip(f"{base_ip}.{start_num}") and 1 <= end_num <= 255
                except ValueError:
                    return False
    
    # Single IP
    return validate_ip(ip_range)

def parse_nmap_output(output):
    """Parse Nmap output and structure it for display"""
    lines = output.split('\n')
    results = {
        'summary': '',
        'hosts': [],
        'raw_output': output
    }
    
    current_host = None
    in_port_section = False
    
    for line in lines:
        line = line.strip()
        
        # Extract summary information
        if 'Nmap scan report for' in line:
            if current_host:
                results['hosts'].append(current_host)
            current_host = {
                'ip': line.split('for ')[-1].split(' ')[0],
                'hostname': '',
                'status': '',
                'ports': [],
                'os_info': '',
                'services': []
            }
            in_port_section = False
            
        elif current_host and 'Host is' in line:
            current_host['status'] = line
            
        elif current_host and line.startswith('PORT'):
            in_port_section = True
            
        elif current_host and in_port_section and '/' in line and 'tcp' in line:
            parts = line.split()
            if len(parts) >= 3:
                port_info = {
                    'port': parts[0],
                    'state': parts[1],
                    'service': parts[2] if len(parts) > 2 else 'unknown'
                }
                current_host['ports'].append(port_info)
                
        elif 'OS' in line and current_host:
            current_host['os_info'] = line
            
        elif line.startswith('Nmap done'):
            results['summary'] = line
    
    if current_host:
        results['hosts'].append(current_host)
    
    return results

def run_nmap_scan_with_sudo_simple(command, password, progress_bar, status_text):
    """Simple sudo scan using echo for password input"""
    try:
        # Create a command that pipes the password to sudo
        # This avoids complex stdin handling
        echo_cmd = f"echo '{password}' | sudo -S {' '.join(command)}"
        
        progress_bar.progress(0.3)
        status_text.text("Running privileged scan with sudo...")
        
        # Run using shell=True to handle the pipe
        process = subprocess.run(
            echo_cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300
        )
        
        progress_bar.progress(1.0)
        status_text.text("Scan completed!")
        
        return process.stdout, process.stderr, process.returncode
        
    except subprocess.TimeoutExpired:
        return "", "Scan timed out after 5 minutes", 1
    except Exception as e:
        return "", f"Error during scan execution: {str(e)}", 1

def run_nmap_scan_with_sudo(command, password, progress_bar, status_text):
    """Run Nmap scan with sudo authentication"""
    try:
        # Create sudo command - keep the full original command
        sudo_command = ['sudo', '-S'] + command
        
        # Update progress to show scan is starting
        progress_bar.progress(0.1)
        status_text.text("Authenticating with sudo...")
        
        # Start the process with sudo and use communicate() directly
        # This avoids manual stdin/stdout handling that can cause I/O errors
        process = subprocess.Popen(
            sudo_command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            universal_newlines=True
        )
        
        try:
            # Update progress
            progress_bar.progress(0.3)
            status_text.text("Running privileged scan...")
            
            # Send password and get all output in one operation
            # This prevents I/O operation on closed file errors
            stdout_data, stderr_data = process.communicate(
                input=password + '\n', 
                timeout=300  # 5 minute timeout
            )
            
            # Update progress
            progress_bar.progress(1.0)
            status_text.text("Scan completed!")
            
            return stdout_data, stderr_data, process.returncode
            
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()  # Clean up zombie process
            return "", "Scan timed out after 5 minutes", 1
        except Exception as e:
            try:
                process.terminate()
                process.wait()  # Clean up zombie process
            except:
                pass
            return "", f"Error during scan execution: {str(e)}", 1
        
    except Exception as e:
        return "", f"Failed to start sudo process: {str(e)}", 1

def run_nmap_scan(command, progress_bar, status_text):
    """Run Nmap scan with progress updates"""
    try:
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
        
        # Read output line by line
        while True:
            output_line = process.stdout.readline()
            if output_line == '' and process.poll() is not None:
                break
            if output_line:
                output += output_line
                # Update status with last line
                status_text.text(f"Scanning... {output_line.strip()}")
                progress_bar.progress(min(len(output) / 1000, 0.9))  # Rough progress estimation
        
        # Get any remaining output
        remaining_output, error_output = process.communicate()
        output += remaining_output
        
        progress_bar.progress(1.0)
        status_text.text("Scan completed!")
        
        return output, error_output, process.returncode
        
    except Exception as e:
        return "", str(e), 1

def create_html_report(scan_results, scan_command):
    """Create an HTML report of the scan results"""
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Nmap Scan Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            .header {{ background-color: #1e3a8a; color: white; padding: 20px; text-align: center; }}
            .summary {{ background-color: #f8fafc; padding: 15px; margin: 20px 0; border-left: 4px solid #3b82f6; }}
            .host {{ margin: 20px 0; padding: 15px; border: 1px solid #e2e8f0; }}
            .host-header {{ background-color: #3b82f6; color: white; padding: 10px; margin: -15px -15px 15px -15px; }}
            .port-table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
            .port-table th, .port-table td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            .port-table th {{ background-color: #f2f2f2; }}
            .open {{ color: #16a34a; font-weight: bold; }}
            .closed {{ color: #dc2626; }}
            .filtered {{ color: #ea580c; }}
            .raw-output {{ background-color: #1f2937; color: #f9fafb; padding: 20px; font-family: monospace; white-space: pre-wrap; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🔍 Nmap Scan Report</h1>
            <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="summary">
            <h2>Scan Command</h2>
            <code>{scan_command}</code>
        </div>
        
        <div class="summary">
            <h2>Summary</h2>
            <p>{scan_results.get('summary', 'Scan completed')}</p>
            <p>Total hosts scanned: {len(scan_results.get('hosts', []))}</p>
        </div>
    """
    
    # Add host information
    for host in scan_results.get('hosts', []):
        html_content += f"""
        <div class="host">
            <div class="host-header">
                <h3>Host: {host['ip']}</h3>
            </div>
            <p><strong>Status:</strong> {host['status']}</p>
        """
        
        if host['ports']:
            html_content += """
            <h4>Open Ports:</h4>
            <table class="port-table">
                <tr><th>Port</th><th>State</th><th>Service</th></tr>
            """
            for port in host['ports']:
                state_class = port['state'].lower()
                html_content += f"""
                <tr>
                    <td>{port['port']}</td>
                    <td class="{state_class}">{port['state']}</td>
                    <td>{port['service']}</td>
                </tr>
                """
            html_content += "</table>"
        
        if host['os_info']:
            html_content += f"<p><strong>OS Info:</strong> {host['os_info']}</p>"
        
        html_content += "</div>"
    
    # Add raw output
    html_content += f"""
        <div class="summary">
            <h2>Raw Nmap Output</h2>
            <div class="raw-output">{scan_results.get('raw_output', '')}</div>
        </div>
    </body>
    </html>
    """
    
    return html_content

def main():
    # Header
    st.markdown('<h1 class="main-header">🔍 XKRed27 Nmap Scanner</h1>', unsafe_allow_html=True)
    
    # Privilege info
    is_privileged = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
    if not is_privileged:
        st.info("💡 **Tip:** Some scan types require elevated privileges. The app will automatically fall back to safe alternatives when needed, or you can run with `sudo streamlit run nmap_ui.py` for full functionality.")
    
    # Sidebar for scan options
    st.sidebar.header("🛠️ Scan Configuration")
    
    # Target input
    st.sidebar.subheader("Target Specification")
    target_input = st.sidebar.text_area(
        "IP Address(es) or Hostname(s)",
        placeholder="192.168.1.1\n192.168.1.0/24\n192.168.1.1-10\nexample.com",
        help="Enter one or more targets (one per line). Supports IP addresses, CIDR notation, ranges, and hostnames."
    )
    
    # Scan type
    st.sidebar.subheader("Scan Type")
    
    # Check if running as root/admin
    is_privileged = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
    
    # Scan types with privilege requirements
    privileged_scans = [
        "TCP SYN Scan (-sS)",
        "UDP Scan (-sU)",
        "TCP ACK Scan (-sA)",
        "TCP Window Scan (-sW)",
        "TCP Maimon Scan (-sM)",
        "OS Detection (-O)",
        "Aggressive Scan (-A)"
    ]
    
    # Non-privileged scans (safe defaults)
    non_privileged_scans = [
        "TCP Connect Scan (-sT)",
        "Ping Scan (-sn)",
        "Version Detection (-sV)"
    ]
    
    # All scan options
    all_scans = [
        "Aggressive Scan (-A)",  # Default for comprehensive scanning
        "TCP Connect Scan (-sT)",
        "TCP SYN Scan (-sS)",
        "UDP Scan (-sU)",
        "TCP ACK Scan (-sA)",
        "TCP Window Scan (-sW)",
        "TCP Maimon Scan (-sM)",
        "Ping Scan (-sn)",
        "Version Detection (-sV)",
        "OS Detection (-O)"
    ]
    
    scan_type = st.sidebar.selectbox(
        "Select scan type",
        all_scans
    )
    
    # Show privilege warning and credential input if needed
    sudo_password = None
    use_sudo = False
    
    # Check if privileged options are selected (either scan type or advanced options)
    needs_privileges = (scan_type in privileged_scans or 
                       advanced_options.get("aggressive_scan", False) or
                       advanced_options.get("os_detection", False)) and not is_privileged
    
    if needs_privileges:
        st.sidebar.warning("⚠️ Selected scan options require root/admin privileges.")
        
        # Credential input section
        st.sidebar.subheader("🔐 Administrator Credentials")
        use_sudo = st.sidebar.checkbox("Use sudo authentication", value=True, help="Enter your password to run privileged scans")
        
        if use_sudo:
            sudo_password = st.sidebar.text_input(
                "Enter your password:",
                type="password",
                help="Your password will be used for sudo authentication and not stored"
            )
            
            # Validate that password is provided
            if not sudo_password:
                st.sidebar.warning("⚠️ Password required for sudo authentication")
            
            st.sidebar.info("💡 Your password is only used for this scan and is not stored anywhere.")
            
            # Security warning
            with st.sidebar.expander("🛡️ Security Information"):
                st.markdown("""
                **How this works:**
                - Password is sent directly to sudo command
                - Password is never stored or logged
                - Connection is local to your machine
                - Password is cleared from memory after use
                
                **Alternative options:**
                - Use TCP Connect Scan (-sT) - no privileges needed
                - Run the app with: `sudo streamlit run nmap_ui.py`
                - Configure passwordless sudo for nmap
                """)
        else:
            st.sidebar.info("💡 Consider using TCP Connect Scan (-sT) which doesn't require privileges.")
    
    # Port specification
    st.sidebar.subheader("Port Specification")
    port_option = st.sidebar.radio(
        "Port selection",
        ["Default ports", "All ports (1-65535)", "Top 1000 ports", "Custom range"]
    )
    
    custom_ports = ""
    if port_option == "Custom range":
        custom_ports = st.sidebar.text_input(
            "Port range",
            placeholder="80,443,8080-8090",
            help="Specify ports or ranges separated by commas"
        )
    
    # Timing and performance
    st.sidebar.subheader("Timing & Performance")
    timing_template = st.sidebar.selectbox(
        "Timing template",
        [
            "Default",
            "Paranoid (-T0)",
            "Sneaky (-T1)",
            "Polite (-T2)",
            "Normal (-T3)",
            "Aggressive (-T4)",
            "Insane (-T5)"
        ],
        index=5  # Default to "Aggressive (-T4)"
    )
    
    # Advanced options
    st.sidebar.subheader("Advanced Options")
    advanced_options = {
        "aggressive_scan": st.sidebar.checkbox("Aggressive scan (-A)", value=True, help="Enable OS detection, version detection, script scanning, and traceroute"),
        "all_ports": st.sidebar.checkbox("All ports scan (-p-)", help="Scan all 65535 ports (1-65535)"),
        "skip_ping": st.sidebar.checkbox("Skip host discovery (-Pn)", help="Treat all hosts as online"),
        "ping_only": st.sidebar.checkbox("Ping scan only (-sn)", help="Only perform host discovery, no port scanning"),
        "fragment_packets": st.sidebar.checkbox("Fragment packets (-f)", help="Fragment IP packets"),
        "decoy_scan": st.sidebar.checkbox("Decoy scan (-D)", help="Cloak scan with decoys"),
        "service_version": st.sidebar.checkbox("Service version detection (-sV)", value=True, help="Probe open ports for service versions"),
        "os_detection": st.sidebar.checkbox("OS detection (-O)", value=True, help="Enable OS detection"),
        "script_scan": st.sidebar.checkbox("Default scripts (-sC)", help="Run default NSE scripts"),
        "verbose": st.sidebar.checkbox("Verbose output (-v)", value=True, help="Increase verbosity level")
    }
    
    # Main content area
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("🎯 Scan Configuration")
        
        # Display current configuration
        if target_input:
            targets = [t.strip() for t in target_input.split('\n') if t.strip()]
            st.write(f"**Targets:** {', '.join(targets)}")
            st.write(f"**Scan Type:** {scan_type}")
            
            # Show advanced options that are enabled
            enabled_advanced = []
            if advanced_options.get("aggressive_scan"):
                enabled_advanced.append("Aggressive (-A)")
            if advanced_options.get("all_ports"):
                enabled_advanced.append("All ports (-p-)")
            if advanced_options.get("service_version"):
                enabled_advanced.append("Service version (-sV)")
            if advanced_options.get("os_detection"):
                enabled_advanced.append("OS detection (-O)")
            if advanced_options.get("verbose"):
                enabled_advanced.append("Verbose (-v)")
            
            if enabled_advanced:
                st.write(f"**Advanced Options:** {', '.join(enabled_advanced)}")
            
            if port_option != "Default ports" and not advanced_options.get("all_ports"):
                st.write(f"**Ports:** {port_option}")
                if custom_ports:
                    st.write(f"**Custom Ports:** {custom_ports}")
            
            if timing_template != "Default":
                st.write(f"**Timing:** {timing_template}")
        
        # Build Nmap command
        if st.button("🚀 Start Scan", type="primary", use_container_width=True):
            if not target_input.strip():
                st.error("Please enter at least one target IP address or hostname.")
            elif needs_privileges and use_sudo and not sudo_password:
                st.error("Please enter your password for sudo authentication, or uncheck 'Use sudo authentication' to use fallback scan.")
            else:
                targets = [t.strip() for t in target_input.split('\n') if t.strip()]
                
                # Validate targets
                invalid_targets = []
                for target in targets:
                    if not (validate_ip(target) or validate_ip_range(target) or 
                           re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target)):
                        invalid_targets.append(target)
                
                if invalid_targets:
                    st.error(f"Invalid targets: {', '.join(invalid_targets)}")
                else:
                    # Build command
                    cmd = ["nmap"]
                    
                    # Add scan type
                    scan_flag = scan_type.split('(')[-1].replace(')', '')
                    if scan_flag != scan_type:  # Has a flag
                        cmd.append(scan_flag)
                    
                    # Add port specification
                    if port_option == "All ports (1-65535)":
                        cmd.extend(["-p", "1-65535"])
                    elif port_option == "Top 1000 ports":
                        cmd.append("--top-ports")
                        cmd.append("1000")
                    elif port_option == "Custom range" and custom_ports:
                        cmd.extend(["-p", custom_ports])
                    
                    # Add timing template
                    if timing_template != "Default":
                        timing_flag = timing_template.split('(')[-1].replace(')', '')
                        if timing_flag != timing_template:
                            cmd.append(timing_flag)
                    
                    # Add advanced options
                    if advanced_options["aggressive_scan"]:
                        cmd.append("-A")
                    if advanced_options["all_ports"]:
                        # Override any existing port specification with all ports
                        # Remove any existing -p flags first
                        cmd = [item for item in cmd if not item.startswith('-p')]
                        cmd.extend(["-p", "-"])
                    if advanced_options["skip_ping"]:
                        cmd.append("-Pn")
                    if advanced_options["ping_only"]:
                        cmd.append("-sn")  # -P is actually -sn in modern nmap
                    if advanced_options["fragment_packets"]:
                        cmd.append("-f")
                    if advanced_options["service_version"]:
                        cmd.append("-sV")
                    if advanced_options["os_detection"]:
                        cmd.append("-O")
                    if advanced_options["script_scan"]:
                        cmd.append("-sC")
                    if advanced_options["verbose"]:
                        cmd.append("-v")
                    
                    # Add output format for parsing
                    cmd.extend(["-oN", "-"])  # Normal output to stdout
                    
                    # Add targets
                    cmd.extend(targets)
                    
                    st.write(f"**Command:** `{' '.join(cmd)}`")
                    
                    # Progress indicators
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    
                    # Run scan (with or without sudo)
                    used_sudo = False
                    with st.spinner("Initializing scan..."):
                        # Check if we should use sudo
                        if sudo_password and needs_privileges:
                            st.info("🔐 Running scan with sudo authentication...")
                            # Try the simple method first (more reliable)
                            output, error, return_code = run_nmap_scan_with_sudo_simple(cmd, sudo_password, progress_bar, status_text)
                            used_sudo = True
                            
                            # If simple method fails with I/O error, try the complex method
                            if return_code != 0 and "I/O operation on closed file" in error:
                                st.warning("⚠️ Trying alternative sudo method...")
                                progress_bar.progress(0.1)
                                output, error, return_code = run_nmap_scan_with_sudo(cmd, sudo_password, progress_bar, status_text)
                            
                            # Clear password from memory immediately
                            sudo_password = None
                            
                            # Check for authentication failure
                            if return_code == 1 and ("incorrect password" in error.lower() or 
                                                    "authentication failure" in error.lower() or
                                                    "sorry, try again" in error.lower() or
                                                    "sudo: 1 incorrect password attempt" in error.lower()):
                                st.error("❌ Authentication failed. Please check your password and try again.")
                                st.info("💡 Make sure you have sudo privileges and entered the correct password.")
                                st.stop()
                            elif return_code != 0 and used_sudo:
                                # Handle other sudo-related errors
                                if "not in the sudoers file" in error.lower():
                                    st.error("❌ Your user account doesn't have sudo privileges.")
                                    st.info("💡 Contact your system administrator or use TCP Connect Scan (-sT) instead.")
                                    st.stop()
                                elif "sudo: command not found" in error.lower():
                                    st.error("❌ sudo command not found on this system.")
                                    st.info("💡 Try running the app with elevated privileges or use TCP Connect Scan (-sT).")
                                    st.stop()
                                elif "I/O operation on closed file" in error:
                                    st.warning("⚠️ Sudo authentication encountered an I/O error. Attempting fallback to TCP Connect scan...")
                                    # Force fallback by setting used_sudo to False
                                    used_sudo = False
                                elif "dnet: Failed to open device" in error or "Failed to open device" in error:
                                    st.warning("⚠️ Network device access denied. This usually happens with advanced scans. Attempting fallback to TCP Connect scan...")
                                    # Force fallback by setting used_sudo to False
                                    used_sudo = False
                        else:
                            output, error, return_code = run_nmap_scan(cmd, progress_bar, status_text)
                    
                    # Handle various scan errors with automatic fallback
                    if return_code == 1 and not used_sudo and (
                        "requires root privileges" in error or
                        "dnet: Failed to open device" in error or
                        "Failed to open device" in error
                    ):
                        # Provide specific warning based on error type
                        if "dnet: Failed to open device" in error or "Failed to open device" in error:
                            st.warning("⚠️ Network device access denied for advanced scan features. Attempting fallback to TCP Connect scan...")
                        else:
                            st.warning("⚠️ Scan requires root privileges. Attempting fallback to TCP Connect scan...")
                        
                        # Create fallback command with TCP Connect scan
                        fallback_cmd = cmd.copy()
                        
                        # Replace privileged scan flags with -sT
                        privileged_flags = ['-sS', '-sU', '-sA', '-sW', '-sM', '-O']
                        for flag in privileged_flags:
                            if flag in fallback_cmd:
                                fallback_cmd[fallback_cmd.index(flag)] = '-sT'
                        
                        # Handle -A flag specially - remove problematic components
                        if '-A' in fallback_cmd:
                            a_index = fallback_cmd.index('-A')
                            if "dnet: Failed to open device" in error:
                                # For device access errors, use minimal safe scan
                                fallback_cmd[a_index:a_index+1] = ['-sT', '-sV']
                            else:
                                # For privilege errors, use more comprehensive safe scan
                                fallback_cmd[a_index:a_index+1] = ['-sT', '-sV', '-sC']
                        
                        # Remove duplicate -sT flags
                        seen = set()
                        fallback_cmd = [x for x in fallback_cmd if not (x == '-sT' and x in seen) and not seen.add(x)]
                        
                        st.write(f"**Fallback Command:** `{' '.join(fallback_cmd)}`")
                        
                        # Run fallback scan
                        progress_bar.progress(0)
                        status_text.text("Running fallback scan...")
                        output, error, return_code = run_nmap_scan(fallback_cmd, progress_bar, status_text)
                    
                    if return_code == 0:
                        st.success("✅ Scan completed successfully!")
                        
                        # Add clear results button
                        col_clear1, col_clear2 = st.columns([1, 4])
                        with col_clear1:
                            if st.button("🔄 Clear & New Scan", help="Clear results and start a new scan"):
                                # Clear session state
                                if 'last_scan_results' in st.session_state:
                                    del st.session_state['last_scan_results']
                                if 'last_scan_command' in st.session_state:
                                    del st.session_state['last_scan_command']
                                st.rerun()
                        
                        # Parse and display results
                        scan_results = parse_nmap_output(output)
                        
                        # Store results in session state for download
                        st.session_state['last_scan_results'] = scan_results
                        st.session_state['last_scan_command'] = ' '.join(cmd)
                        
                        # Display results
                        st.subheader("📊 Scan Results")
                        
                        if scan_results['hosts']:
                            for i, host in enumerate(scan_results['hosts']):
                                with st.expander(f"🖥️ Host: {host['ip']}", expanded=True):
                                    st.write(f"**Status:** {host['status']}")
                                    
                                    if host['ports']:
                                        st.write("**Open Ports:**")
                                        port_df = pd.DataFrame(host['ports'])
                                        st.dataframe(port_df, use_container_width=True)
                                    
                                    if host['os_info']:
                                        st.write(f"**OS Information:** {host['os_info']}")
                        else:
                            st.info("No hosts found or scan results could not be parsed.")
                        
                        # Raw output
                        with st.expander("🔍 Raw Nmap Output"):
                            st.code(output, language="text")
                            
                    else:
                        st.error(f"❌ Scan failed with return code {return_code}")
                        if error:
                            st.error(f"Error: {error}")
                        if output:
                            st.code(output, language="text")
                        
                        # Add clear button for failed scans too
                        if st.button("🔄 Try New Scan", help="Clear and try a different scan"):
                            st.rerun()
    
    with col2:
        st.subheader("📥 Download Results")
        
        if 'last_scan_results' in st.session_state:
            # HTML Report
            html_report = create_html_report(
                st.session_state['last_scan_results'],
                st.session_state['last_scan_command']
            )
            
            st.download_button(
                label="📄 Download HTML Report",
                data=html_report,
                file_name=f"nmap_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                mime="text/html",
                use_container_width=True
            )
            
            # JSON Report
            json_report = json.dumps(st.session_state['last_scan_results'], indent=2)
            st.download_button(
                label="📋 Download JSON Report",
                data=json_report,
                file_name=f"nmap_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True
            )
            
            # Raw Output
            st.download_button(
                label="📝 Download Raw Output",
                data=st.session_state['last_scan_results']['raw_output'],
                file_name=f"nmap_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain",
                use_container_width=True
            )
        else:
            st.info("Run a scan to enable downloads")
        
        # Help section
        st.subheader("ℹ️ Help & Tips")
        
        # Privilege status
        with st.expander("🔐 Privilege Status"):
            if is_privileged:
                st.success("✅ Running with elevated privileges - all scan types available")
            else:
                st.info("ℹ️ Running without elevated privileges - some scan types may require root/admin")
                st.markdown("""
                **To run privileged scans:**
                - **Linux/macOS:** `sudo streamlit run nmap_ui.py`
                - **Windows:** Run as Administrator
                
                **Safe non-privileged scans:**
                - TCP Connect Scan (-sT)
                - Ping Scan (-sn)  
                - Version Detection (-sV)
                
                **Common Issues:**
                - "dnet: Failed to open device" → Use TCP Connect (-sT)
                - Network interface access → Requires elevated privileges
                - OS Detection (-O) → Often needs root access
                """)
        
        with st.expander("Target Formats"):
            st.markdown("""
            - **Single IP:** `192.168.1.1`
            - **IP Range:** `192.168.1.1-10`
            - **CIDR:** `192.168.1.0/24`
            - **Hostname:** `example.com`
            - **Multiple:** One per line
            """)
        
        with st.expander("Common Scan Types"):
            st.markdown("""
            - **Aggressive (-A):** 🔥 **Default** - Comprehensive scan with OS, version, scripts
            - **TCP Connect (-sT):** Safe fallback, doesn't require privileges
            - **TCP SYN (-sS):** Fast, stealthy, requires privileges
            - **UDP (-sU):** Scan UDP ports
            - **Ping Scan (-sn):** Host discovery only
            - **Version Detection (-sV):** Service versions
            - **OS Detection (-O):** Operating system detection
            """)

if __name__ == "__main__":
    main()
